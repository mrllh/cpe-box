package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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

	// forwards: key = fmt.Sprintf("%s:%d", agentID, remotePort)
	forwards = make(map[string]*Forward)
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
	go startAPIServer(":8080")
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

		case "port-forward":
			if len(args) < 4 {
				fmt.Println("usage: port-forward <agent-id> <remote-port> <agent-local-addr:port>")
				continue
			}
			agentID := args[1]
			remotePort, err := strconv.Atoi(args[2])
			if err != nil {
				fmt.Println("invalid remote-port:", args[2])
				continue
			}
			targetAddr := args[3]
			if err := startPortForwarding(agentID, remotePort, targetAddr); err != nil {
				fmt.Printf("start port-forward err: %v\n", err)
			} else {
				fmt.Printf("Port-forward started on :%d -> %s (agent=%s)\n", remotePort, targetAddr, agentID)
			}

		case "list-forwards":
			fl := listForwards()
			if len(fl) == 0 {
				fmt.Println("no forwards")
			} else {
				fmt.Println("forwards:")
				for _, v := range fl {
					fmt.Printf(" - agent=%s remote_port=%d target=%s started=%s active_conn=%d\n",
						v.AgentID, v.RemotePort, v.TargetAddr, v.StartedAt.Format(time.RFC3339), v.ActiveConnCount)
				}
			}

		case "stop-port-forward":
			// usage: stop-port-forward <agent-id> <remote-port>
			if len(args) < 3 {
				fmt.Println("usage: stop-port-forward <agent-id> <remote-port>")
				continue
			}
			agentID := args[1]
			p, err := strconv.Atoi(args[2])
			if err != nil {
				fmt.Println("invalid port:", args[2])
				continue
			}
			if err := stopPortForwarding(agentID, p); err != nil {
				fmt.Println("stop failed:", err)
			} else {
				fmt.Printf("stopped forward %s:%d\n", agentID, p)
			}

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
	// open file twice: once to compute hash, second to stream
	fmeta, err := os.Open(path)
	if err != nil {
		return err
	}
	// compute total size and sha256
	fi, _ := fmeta.Stat()
	totalSize := fi.Size()

	h := sha256.New()
	if _, err := io.Copy(h, fmeta); err != nil {
		fmeta.Close()
		return fmt.Errorf("compute sha256 err: %w", err)
	}
	sum := h.Sum(nil)
	shaHex := hex.EncodeToString(sum)
	fmeta.Close()

	// reopen for streaming
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	filename := filepath.Base(path)
	transferID := fmt.Sprintf("%s-%d", agentID, time.Now().UnixNano())

	// find agent session
	mu.Lock()
	ac, ok := agents[agentID]
	mu.Unlock()
	if !ok {
		return fmt.Errorf("no such agent: %s", agentID)
	}

	// open stream
	stream, err := ac.session.Open()
	if err != nil {
		return fmt.Errorf("open stream err: %w", err)
	}
	defer stream.Close()

	// send meta chunk (Chunk nil, but total_size & sha256 fields set)
	meta := &pb.FileChunk{
		TransferId: transferID,
		Chunk:      nil,
		Last:       false,
		Filename:   filename,
		TotalSize:  totalSize,
		Sha256:     shaHex,
	}
	if err := framing.WriteMessage(stream, &pb.Envelope{Payload: &pb.Envelope_FileChunk{FileChunk: meta}}); err != nil {
		return fmt.Errorf("send meta err: %w", err)
	}
	sugar.Infof("Sent meta for transfer %s filename=%s size=%d sha256=%s", transferID, filename, totalSize, shaHex)

	// send file in chunks
	buf := make([]byte, 64*1024) // 64KB chunk
	idx := 0
	sent := int64(0)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			chunkBytes := append([]byte(nil), buf[:n]...) // copy slice
			chunk := &pb.FileChunk{
				TransferId: transferID,
				Chunk:      chunkBytes,
				Last:       false,
				Filename:   filename,
			}
			if err := framing.WriteMessage(stream, &pb.Envelope{Payload: &pb.Envelope_FileChunk{FileChunk: chunk}}); err != nil {
				return fmt.Errorf("write chunk err: %w", err)
			}
			idx++
			sent += int64(n)
			sugar.Infof("Sent chunk #%d size=%d transfer=%s progress=%d/%d", idx, n, transferID, sent, totalSize)
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
			sugar.Infof("Sent final marker for transfer %s chunks=%d total_sent=%d", transferID, idx, sent)
			break
		}
		if rerr != nil {
			return fmt.Errorf("read file err: %w", rerr)
		}
	}

	return nil
}

func startPortForwarding(agentID string, remotePort int, targetAddr string) error {
	key := fmt.Sprintf("%s:%d", agentID, remotePort)

	mu.Lock()
	if _, exists := forwards[key]; exists {
		mu.Unlock()
		return fmt.Errorf("forward already exists for %s", key)
	}
	mu.Unlock()

	listenAddr := fmt.Sprintf(":%d", remotePort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s err: %w", listenAddr, err)
	}

	f := newForward(agentID, remotePort, targetAddr, ln)

	mu.Lock()
	forwards[key] = f
	mu.Unlock()

	go func() {
		sugar.Infof("port-forward listener started %s -> %s (agent=%s)", listenAddr, targetAddr, agentID)
		defer func() {
			ln.Close()
			mu.Lock()
			delete(forwards, key)
			mu.Unlock()
			sugar.Infof("port-forward listener closed %s (agent=%s)", listenAddr, agentID)
		}()

		for {
			conn, err := ln.Accept()
			if err != nil {
				sugar.Warnf("accept on %s err: %v", listenAddr, err)
				return
			}
			go func(c net.Conn) {
				if err := forwardConnToAgent(key, agentID, c, targetAddr); err != nil {
					sugar.Warnf("forwardConnToAgent err: %v", err)
					_ = c.Close()
				}
			}(conn)
		}
	}()

	return nil
}

func forwardConnToAgent(key string, agentID string, c net.Conn, targetAddr string) error {
	mu.Lock()
	f, ok := forwards[key]
	mu.Unlock()
	if !ok {
		return fmt.Errorf("no forward for key %s", key)
	}

	// open new stream on this agent's session
	mu.Lock()
	ac, ok := agents[agentID]
	mu.Unlock()
	if !ok {
		return fmt.Errorf("no such agent: %s", agentID)
	}

	stream, err := ac.session.Open()
	if err != nil {
		return fmt.Errorf("open stream to agent err: %w", err)
	}

	// send PortForward metadata first
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())
	pf := &pb.PortForward{
		ReqId:      reqID,
		Proto:      "tcp",
		TargetAddr: targetAddr,
	}
	if err := framing.WriteMessage(stream, &pb.Envelope{Payload: &pb.Envelope_PortForward{PortForward: pf}}); err != nil {
		stream.Close()
		return fmt.Errorf("send portforward meta err: %w", err)
	}

	// register this connection in Forward
	connID := fmt.Sprintf("%d", time.Now().UnixNano())
	fc := &ForwardConn{Ext: c, Stream: stream}
	f.addConn(connID, fc)

	done := make(chan struct{}, 2)

	// client -> stream
	go func() {
		_, err := io.Copy(stream, c)
		if err != nil {
			sugar.Warnf("copy client->stream err: %v", err)
		}
		// try to close stream write side; Close will fire EOF to agent side
		_ = stream.Close()
		done <- struct{}{}
	}()

	// stream -> client
	go func() {
		_, err := io.Copy(c, stream)
		if err != nil {
			sugar.Warnf("copy stream->client err: %v", err)
		}
		// close client connection
		_ = c.Close()
		done <- struct{}{}
	}()

	// wait for one goroutine to finish
	<-done

	// cleanup: remove conn entry (also closes both sides again to be safe)
	f.removeConn(connID)
	return nil
}

func stopPortForwarding(agentID string, remotePort int) error {
	key := fmt.Sprintf("%s:%d", agentID, remotePort)
	mu.Lock()
	f, ok := forwards[key]
	mu.Unlock()
	if !ok {
		return fmt.Errorf("no forward for %s", key)
	}
	// first stop accepting new connections
	if f.Listener != nil {
		_ = f.Listener.Close()
	}
	// then close all active connections (streams + external conns)
	f.closeAll()

	mu.Lock()
	delete(forwards, key)
	mu.Unlock()
	sugar.Infof("stopped forward %s", key)
	return nil
}

type ForwardInfo struct {
	AgentID         string    `json:"agent"`
	RemotePort      int       `json:"remote_port"`
	TargetAddr      string    `json:"target_addr"`
	StartedAt       time.Time `json:"started_at"`
	ActiveConnCount int       `json:"active_conn_count"`
}

func listForwards() []ForwardInfo {
	mu.Lock()
	defer mu.Unlock()
	res := []ForwardInfo{}
	for k, f := range forwards {
		f.mu.Lock()
		count := len(f.Conns)
		f.mu.Unlock()
		info := ForwardInfo{
			AgentID:         f.AgentID,
			RemotePort:      f.RemotePort,
			TargetAddr:      f.TargetAddr,
			StartedAt:       f.StartedAt,
			ActiveConnCount: count,
		}
		// optionally include key
		_ = k
		res = append(res, info)
	}
	return res
}

func startAPIServer(addr string) {
	r := gin.Default()

	// simple token auth middleware if env AGENT_ADMIN_TOKEN set
	adminToken := os.Getenv("AGENT_ADMIN_TOKEN")
	if adminToken != "" {
		r.Use(func(c *gin.Context) {
			t := c.GetHeader("X-Admin-Token")
			if t == "" {
				t = c.Query("token")
			}
			if t != adminToken {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			c.Next()
		})
	}

	r.GET("/api/agents", func(c *gin.Context) {
		mu.Lock()
		ids := make([]string, 0, len(agents))
		for id := range agents {
			ids = append(ids, id)
		}
		mu.Unlock()
		c.JSON(200, gin.H{"agents": ids})
	})

	type RunShellReq struct {
		Cmd     string `json:"cmd"`
		Timeout int    `json:"timeout"`
	}
	r.POST("/api/agents/:id/run", func(c *gin.Context) {
		id := c.Param("id")
		var body RunShellReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, gin.H{"error": "invalid json"})
			return
		}
		if body.Cmd == "" {
			c.JSON(400, gin.H{"error": "cmd required"})
			return
		}
		res, err := sendRunShellSync(id, body.Cmd, body.Timeout)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"ok": res.Ok, "output": res.Output})
	})

	type PFStartReq struct {
		RemotePort int    `json:"remote_port"`
		TargetAddr string `json:"target_addr"`
	}
	r.POST("/api/agents/:id/port-forward", func(c *gin.Context) {
		id := c.Param("id")
		var body PFStartReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, gin.H{"error": "invalid json"})
			return
		}
		if body.RemotePort <= 0 || body.TargetAddr == "" {
			c.JSON(400, gin.H{"error": "remote_port and target_addr required"})
			return
		}
		if err := startPortForwarding(id, body.RemotePort, body.TargetAddr); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"status": "started"})
	})

	type PFStopReq struct {
		RemotePort int `json:"remote_port"`
	}
	r.POST("/api/agents/:id/port-forward/stop", func(c *gin.Context) {
		id := c.Param("id")
		var body PFStopReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, gin.H{"error": "invalid json"})
			return
		}
		if body.RemotePort <= 0 {
			c.JSON(400, gin.H{"error": "remote_port required"})
			return
		}
		if err := stopPortForwarding(id, body.RemotePort); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"status": "stopped"})
	})

	r.GET("/api/forwards", func(c *gin.Context) {
		c.JSON(200, gin.H{"forwards": listForwards()})
	})

	sugar.Infof("admin API listening on %s", addr)
	if err := r.Run(addr); err != nil {
		sugar.Fatalf("admin API run err: %v", err)
	}
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  list                           - List all connected agents")
	fmt.Println("  msg <agent-id> <text>          - Send text message to agent")
	fmt.Println("  restart <agent-id>             - Restart a specific agent")
	fmt.Println("  upload <agent-id> <filepath>   - Upload file to agent (new yamux stream)")
	fmt.Println("  run-shell <agent-id> <cmd...>  - Run shell on agent and wait for result")
	fmt.Println("  port-forward <agent-id> <remote-port> <agent-local-addr:port> - Start port forwarding")
	fmt.Println("  stop-port-forward <agent-id> <remote-port> - Stop a port forward")
	fmt.Println("  list-forwards                  - List active port forwards")
	fmt.Println("  help                           - Show this help")
}

type ForwardConn struct {
	Ext    net.Conn
	Stream net.Conn
}

type Forward struct {
	AgentID    string
	RemotePort int
	TargetAddr string
	Listener   net.Listener
	Conns      map[string]*ForwardConn // key = ext.RemoteAddr().String()
	StartedAt  time.Time
	mu         sync.Mutex
}

func newForward(agentID string, remotePort int, targetAddr string, ln net.Listener) *Forward {
	return &Forward{
		AgentID:    agentID,
		RemotePort: remotePort,
		TargetAddr: targetAddr,
		Listener:   ln,
		Conns:      make(map[string]*ForwardConn),
		StartedAt:  time.Now(),
	}
}

func (f *Forward) addConn(id string, fc *ForwardConn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Conns[id] = fc
}

func (f *Forward) removeConn(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.Conns[id]; ok {
		// ensure both sides closed
		_ = c.Ext.Close()
		_ = c.Stream.Close()
		delete(f.Conns, id)
	}
}

func (f *Forward) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, c := range f.Conns {
		_ = c.Ext.Close()
		_ = c.Stream.Close()
		delete(f.Conns, id)
	}
}
