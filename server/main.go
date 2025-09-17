package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"cpe-box/internal/framing"
	"cpe-box/pb"
)

type AgentConn struct {
	id       string
	stream   net.Conn
	sendCh   chan proto.Message
	lastSeen time.Time
	session  *yamux.Session
	logger   *zap.Logger
	closed   chan struct{}
}

var (
	mu      sync.Mutex
	agents  = make(map[string]*AgentConn)
	pending = make(map[string]chan *pb.CommandResult) // req_id -> chan
	sugar   *zap.SugaredLogger
)

func main() {
	addr := flag.String("addr", ":9999", "listen address")
	tlsCert := flag.String("tls-cert", "", "tls cert path")
	tlsKey := flag.String("tls-key", "", "tls key path")
	flag.Parse()

	zl, _ := zap.NewProduction()
	defer zl.Sync()
	sugar = zl.Sugar()

	var ln net.Listener
	var err error
	if *tlsCert != "" && *tlsKey != "" {
		cert, lerr := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if lerr == nil {
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
			ln, err = tls.Listen("tcp", *addr, cfg)
		} else {
			sugar.Warnf("load cert err: %v, fallback to plain tcp", lerr)
		}
	}
	if ln == nil {
		ln, err = net.Listen("tcp", *addr)
	}
	if err != nil {
		sugar.Fatalf("listen err: %v", err)
	}
	defer ln.Close()
	sugar.Infof("server listening on %s", *addr)

	go acceptLoop(ln)
	console()
}

func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			sugar.Warnf("accept err: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(raw net.Conn) {
	defer raw.Close()
	session, err := yamux.Server(raw, nil)
	if err != nil {
		sugar.Warnf("yamux server err: %v", err)
		return
	}
	for {
		stream, err := session.Accept()
		if err != nil {
			sugar.Infof("session accept err: %v", err)
			return
		}
		go handleStream(stream, session)
	}
}

func handleStream(stream net.Conn, session *yamux.Session) {
	sugar.Infof("stream from %s", stream.RemoteAddr())

	// first message must be Register
	var env pb.Envelope
	if err := framing.ReadMessage(stream, &env); err != nil {
		sugar.Warnf("failed to read register: %v", err)
		stream.Close()
		return
	}
	reg, ok := env.Payload.(*pb.Envelope_Register)
	if !ok {
		sugar.Warn("first payload not Register")
		stream.Close()
		return
	}
	id := reg.Register.Id

	ac := &AgentConn{
		id:       id,
		stream:   stream,
		sendCh:   make(chan proto.Message, 32),
		lastSeen: time.Now(),
		session:  session,
		logger:   zap.NewExample(),
		closed:   make(chan struct{}),
	}
	mu.Lock()
	agents[id] = ac
	mu.Unlock()
	sugar.Infof("agent %s registered", id)

	// writer
	go agentWriter(ac)

	// reader loop
	for {
		var env pb.Envelope
		if err := framing.ReadMessage(stream, &env); err != nil {
			if err == io.EOF {
				sugar.Infof("agent %s closed stream", id)
			} else {
				sugar.Warnf("read err from %s: %v", id, err)
			}
			break
		}
		ac.lastSeen = time.Now()
		switch x := env.Payload.(type) {
		case *pb.Envelope_Heartbeat:
			// ignore or update metrics
		case *pb.Envelope_Message:
			sugar.Infof("message from %s: %s", id, x.Message.Body)
		case *pb.Envelope_Result:
			handleCommandResult(x.Result)
		case *pb.Envelope_FileChunk:
			sugar.Infof("file chunk from %s (unexpected)", id)
		default:
			sugar.Infof("unknown payload from %s", id)
		}
	}

	// cleanup
	close(ac.closed)
	mu.Lock()
	delete(agents, id)
	mu.Unlock()
	stream.Close()
	sugar.Infof("agent %s disconnected", id)
}

func agentWriter(ac *AgentConn) {
	for {
		select {
		case msg := <-ac.sendCh:
			if err := framing.WriteMessage(ac.stream, msg); err != nil {
				sugar.Warnf("write to %s failed: %v", ac.id, err)
				return
			}
		case <-ac.closed:
			return
		}
	}
}

func handleCommandResult(res *pb.CommandResult) {
	sugar.Infof("CommandResult from %s req_id=%s ok=%v", res.TargetId, res.ReqId, res.Ok)
	// deliver to pending if any
	mu.Lock()
	ch, ok := pending[res.ReqId]
	if ok {
		select {
		case ch <- res:
		default:
		}
		delete(pending, res.ReqId)
	}
	mu.Unlock()
	// also log the output
	sugar.Infof("Output: %s", res.Output)
}

func sendCommandToAgent(agentID string, cmd *pb.Command) error {
	mu.Lock()
	ac, ok := agents[agentID]
	mu.Unlock()
	if !ok {
		return fmt.Errorf("no such agent")
	}
	env := &pb.Envelope{Payload: &pb.Envelope_Command{Command: cmd}}
	select {
	case ac.sendCh <- env:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout sending to agent")
	}
}

func sendRunShellSync(agentID, cmdStr string, timeoutSec int) (*pb.CommandResult, error) {
	reqID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix()%1000)
	payload := map[string]interface{}{
		"cmd":     cmdStr,
		"timeout": timeoutSec,
		"req_id":  reqID,
	}
	bs, _ := json.Marshal(payload)
	pbCmd := &pb.Command{Type: pb.CommandType_RUN_SHELL, TargetId: agentID, Payload: string(bs)}

	ch := make(chan *pb.CommandResult, 1)
	mu.Lock()
	pending[reqID] = ch
	mu.Unlock()

	if err := sendCommandToAgent(agentID, pbCmd); err != nil {
		mu.Lock()
		delete(pending, reqID)
		mu.Unlock()
		return nil, err
	}

	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	select {
	case res := <-ch:
		return res, nil
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		mu.Lock()
		delete(pending, reqID)
		mu.Unlock()
		return nil, fmt.Errorf("timeout waiting for result (req=%s)", reqID)
	}
}

func console() {
	reader := bufio.NewReader(os.Stdin)
	printHelp()

	for {
		fmt.Print("> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("read input error: %v\n", err)
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		args := splitArgs(line)
		if len(args) == 0 {
			continue
		}

		switch args[0] {
		case "help":
			printHelp()

		case "list":
			listAgents()

		case "msg":
			// usage: msg <agent-id> <text...>
			if len(args) < 3 {
				fmt.Println("usage: msg <agent-id> <text>")
				continue
			}
			agentID := args[1]
			text := strings.Join(args[2:], " ")
			sendMessage(agentID, text)
			fmt.Printf("Sent message to %s\n", agentID)

		case "restart":
			// usage: restart <agent-id>
			if len(args) < 2 {
				fmt.Println("usage: restart <agent-id>")
				continue
			}
			agentID := args[1]
			cmd := &pb.Command{
				Type:     pb.CommandType_RESTART,
				TargetId: agentID,
				Payload:  "",
			}
			if err := sendCommandToAgent(agentID, cmd); err != nil {
				fmt.Printf("failed to send restart to %s: %v\n", agentID, err)
			} else {
				fmt.Printf("Sent restart to %s\n", agentID)
			}

		case "upload":
			// usage: upload <agent-id> <filepath>
			if len(args) < 3 {
				fmt.Println("usage: upload <agent-id> <filepath>")
				continue
			}
			agentID := args[1]
			path := args[2]
			go func() {
				fmt.Printf("Start uploading %s -> %s\n", path, agentID)
				if err := uploadFileNewStream(agentID, path); err != nil {
					fmt.Printf("upload error for %s: %v\n", agentID, err)
				} else {
					fmt.Printf("upload finished: %s -> %s\n", path, agentID)
				}
			}()

		case "run-shell":
			// usage: run-shell <agent-id> <cmd...>
			if len(args) < 3 {
				fmt.Println("usage: run-shell <agent-id> <cmd...>")
				continue
			}
			agentID := args[1]
			cmdStr := strings.Join(args[2:], " ")
			// default timeout 30s; you can tweak or extend syntax to pass timeout
			timeout := 30
			fmt.Printf("Sending run-shell to %s: %s\n", agentID, cmdStr)
			res, err := sendRunShellSync(agentID, cmdStr, timeout)
			if err != nil {
				fmt.Printf("run-shell error: %v\n", err)
				continue
			}
			fmt.Printf("Result from %s (ok=%v):\n%s\n", agentID, res.Ok, res.Output)

		default:
			fmt.Println("Unknown command. Type 'help' for usage.")
		}
	}
}

func splitArgs(line string) []string {
	var res []string
	cur := ""
	inq := false
	for _, r := range line {
		if r == '"' {
			inq = !inq
			continue
		}
		if r == ' ' && !inq {
			if cur != "" {
				res = append(res, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		res = append(res, cur)
	}
	return res
}

func listAgents() {
	mu.Lock()
	defer mu.Unlock()
	if len(agents) == 0 {
		fmt.Println("no agents")
		return
	}
	fmt.Println("agents:")
	for id, a := range agents {
		fmt.Printf(" - %s (lastSeen=%v)\n", id, a.lastSeen)
	}
}

func sendMessage(agentID, text string) {
	mu.Lock()
	ac, ok := agents[agentID]
	mu.Unlock()
	if !ok {
		fmt.Println("no such agent")
		return
	}
	env := &pb.Envelope{Payload: &pb.Envelope_Message{Message: &pb.Message{From: "server", Body: text}}}
	ac.sendCh <- env
}

func uploadFileNewStream(agentID, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// stat, _ := f.Stat()
	filename := filepath.Base(path)
	transferID := fmt.Sprintf("%s-%d", agentID, time.Now().UnixNano())

	// get agent session
	mu.Lock()
	ac, ok := agents[agentID]
	mu.Unlock()
	if !ok {
		return fmt.Errorf("no such agent: %s", agentID)
	}

	// open a new yamux stream to the agent
	stream, err := ac.session.Open()
	if err != nil {
		return fmt.Errorf("open stream err: %w", err)
	}
	defer stream.Close()

	// send initial meta chunk (filename, transfer_id)
	meta := &pb.FileChunk{
		TransferId: transferID,
		Chunk:      nil,
		Last:       false,
		Filename:   filename,
	}
	if err := framing.WriteMessage(stream, &pb.Envelope{Payload: &pb.Envelope_FileChunk{FileChunk: meta}}); err != nil {
		return fmt.Errorf("send meta err: %w", err)
	}

	// stream file in chunks
	buf := make([]byte, 64*1024) // 64KB chunk
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			chunk := &pb.FileChunk{
				TransferId: transferID,
				Chunk:      append([]byte(nil), buf[:n]...), // copy
				Last:       false,
				Filename:   filename,
			}
			if err := framing.WriteMessage(stream, &pb.Envelope{Payload: &pb.Envelope_FileChunk{FileChunk: chunk}}); err != nil {
				return fmt.Errorf("write chunk err: %w", err)
			}
		}
		if rerr == io.EOF {
			// send final marker
			last := &pb.FileChunk{
				TransferId: transferID,
				Chunk:      nil,
				Last:       true,
				Filename:   filename,
			}
			if err := framing.WriteMessage(stream, &pb.Envelope{Payload: &pb.Envelope_FileChunk{FileChunk: last}}); err != nil {
				return fmt.Errorf("write last err: %w", err)
			}
			break
		}
		if rerr != nil {
			return fmt.Errorf("read file err: %w", rerr)
		}
	}

	return nil
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  list                           - List all connected agents")
	fmt.Println("  msg <agent-id> <text>          - Send text message to agent")
	fmt.Println("  restart <agent-id>             - Restart a specific agent")
	fmt.Println("  upload <agent-id> <filepath>   - Upload file to agent (new yamux stream)")
	fmt.Println("  run-shell <agent-id> <cmd...>  - Run shell on agent and wait for result")
	fmt.Println("  help                           - Show this help")
}
