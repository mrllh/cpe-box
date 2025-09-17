package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"

	"cpe-box/internal/framing"
	"cpe-box/pb"
)

const defaultServerAddr = "127.0.0.1:9999"

var (
	agentID string
	logger  *zap.SugaredLogger
)

func dialServer(addr string) (net.Conn, error) {
	useTLS := os.Getenv("AGENT_TLS") == "1" || os.Getenv("AGENT_TLS") == "true"
	if !useTLS {
		return net.Dial("tcp", addr)
	}

	skipVerify := os.Getenv("AGENT_TLS_SKIP_VERIFY") == "1" || os.Getenv("AGENT_TLS_SKIP_VERIFY") == "true"
	caPath := os.Getenv("AGENT_TLS_CA")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}

	if caPath != "" {
		bs, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(bs) {
			return nil, fmt.Errorf("failed to append CA cert")
		}
		tlsConfig.RootCAs = pool
		tlsConfig.InsecureSkipVerify = false
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func main() {
	flag.StringVar(&agentID, "id", "agent-123", "unique agent id")
	flag.Parse()

	lg, _ := zap.NewProduction()
	defer lg.Sync()
	logger = lg.Sugar()

	udsPath := os.Getenv("CPE_AGENT_SOCK")
	if udsPath == "" {
		udsPath = "/tmp/cpe_agent.sock"
	}

	// supervisor heartbeats
	go supervisorLoop(udsPath)

	// dial server (TLS if configured via env)
	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = defaultServerAddr
	}
	conn, err := dialServer(serverAddr)
	if err != nil {
		logger.Fatalf("dial server err: %v", err)
	}
	defer conn.Close()

	session, err := yamux.Client(conn, nil)
	if err != nil {
		logger.Fatalf("yamux client err: %v", err)
	}
	logger.Infof("yamux session established to %s", serverAddr)

	go acceptStreamLoop(session)

	// open persistent control stream
	stream, err := session.Open()
	if err != nil {
		logger.Fatalf("open stream err: %v", err)
	}
	defer stream.Close()

	// register (include optional token)
	token := os.Getenv("AGENT_TOKEN")
	reg := &pb.Envelope{Payload: &pb.Envelope_Register{Register: &pb.Register{Id: agentID, Token: token}}}
	if err := framing.WriteMessage(stream, reg); err != nil {
		logger.Fatalf("write register err: %v", err)
	}
	logger.Infof("registered id=%s", agentID)

	// read loop
	for {
		var env pb.Envelope
		if err := framing.ReadMessage(stream, &env); err != nil {
			if err == io.EOF {
				logger.Info("server closed stream")
			} else {
				logger.Warnf("read err: %v", err)
			}
			return
		}
		switch x := env.Payload.(type) {
		case *pb.Envelope_Command:
			handleCommand(x.Command, udsPath, stream)
		case *pb.Envelope_Message:
			logger.Infof("message from server: %s", x.Message.Body)
		case *pb.Envelope_FileChunk:
			handleFileChunk(x.FileChunk)
		default:
			logger.Infof("unknown envelope payload")
		}
	}
}

func supervisorLoop(udsPath string) {
	for {
		conn, err := net.Dial("unix", udsPath)
		if err != nil {
			fmt.Println("connect supervisor fail:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for {
			_, err := conn.Write([]byte(agentID + " alive\n"))
			if err != nil {
				break
			}
			time.Sleep(5 * time.Second)
		}
		conn.Close()
	}
}

func handleCommand(cmd *pb.Command, udsPath string, stream net.Conn) {
	logger.Infof("received command: %+v", cmd)
	switch cmd.Type {
	case pb.CommandType_RESTART:
		conn, err := net.Dial("unix", udsPath)
		if err != nil {
			logger.Warnf("cannot notify supervisor: %v", err)
			return
		}
		_, _ = conn.Write([]byte("restart"))
		conn.Close()
		os.Exit(0)

	case pb.CommandType_RUN_SHELL:
		go runShellAndReport(cmd.Payload, stream)

	case pb.CommandType_UPLOAD_FILE:
		logger.Infof("expect file upload: %s", cmd.Payload)
	default:
		logger.Warnf("unknown command type: %v", cmd.Type)
	}
}

func runShellAndReport(payload string, stream net.Conn) {
	// payload expected JSON {"cmd":"...","timeout":30,"req_id":"..."}; fallback: raw string is command
	var req struct {
		Cmd     string `json:"cmd"`
		Timeout int    `json:"timeout"`
		ReqID   string `json:"req_id"`
	}
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		req.Cmd = payload
		req.Timeout = 60
	}
	if req.Timeout <= 0 {
		req.Timeout = 60
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout)*time.Second)
	defer cancel()

	c := exec.CommandContext(ctx, "bash", "-c", req.Cmd)
	out, err := c.CombinedOutput()

	res := &pb.CommandResult{
		TargetId: agentID,
		Ok:       err == nil,
		Output:   string(out),
		ReqId:    req.ReqID,
	}
	env := &pb.Envelope{Payload: &pb.Envelope_Result{Result: res}}
	if err := framing.WriteMessage(stream, env); err != nil {
		logger.Warnf("failed to send command result: %v", err)
	} else {
		logger.Infof("sent command result for req=%s", req.ReqID)
	}
}

var fileBuffers = map[string]*os.File{}

func handleFileChunk(ch *pb.FileChunk) {
	path := filepath.Join("/tmp", ch.TransferId+"_"+ch.Filename)
	if ch.Last {
		if f, ok := fileBuffers[ch.TransferId]; ok {
			f.Close()
			delete(fileBuffers, ch.TransferId)
			logger.Infof("file %s received finished -> %s", ch.Filename, path)
		}
		return
	}
	f, ok := fileBuffers[ch.TransferId]
	var err error
	if !ok {
		f, err = os.Create(path)
		if err != nil {
			logger.Warnf("create file fail: %v", err)
			return
		}
		fileBuffers[ch.TransferId] = f
	}
	_, err = f.Write(ch.Chunk)
	if err != nil {
		logger.Warnf("write chunk fail: %v", err)
		return
	}
}

func acceptStreamLoop(session *yamux.Session) {
	for {
		stream, err := session.Accept()
		if err != nil {
			logger.Warnf("session.Accept error: %v", err)
			return
		}
		go handleFileStream(stream)
	}
}

func handleFileStream(stream net.Conn) {
	defer stream.Close()

	var file *os.File
	for {
		var env pb.Envelope
		if err := framing.ReadMessage(stream, &env); err != nil {
			if err == io.EOF {
				logger.Infof("file stream closed")
			} else {
				logger.Warnf("read chunk err: %v", err)
			}
			if file != nil {
				file.Close()
			}
			return
		}

		fch, ok := env.Payload.(*pb.Envelope_FileChunk)
		if !ok {
			logger.Warnf("unexpected envelope on file stream")
			continue
		}
		fc := fch.FileChunk
		if fc.TransferId == "" {
			logger.Warnf("file chunk missing transfer_id")
			continue
		}

		// prepare path
		path := filepath.Join("/tmp", fc.TransferId+"_"+fc.Filename)

		if fc.Last {
			// finish
			if file != nil {
				file.Close()
				file = nil
				logger.Infof("received file finished: %s", path)
			} else {
				// zero-length file: create empty file
				f0, err := os.Create(path)
				if err == nil {
					f0.Close()
				}
			}
			return // done for this stream
		}

		// open file if not yet
		if file == nil {
			f, err := os.Create(path)
			if err != nil {
				logger.Warnf("create file err: %v", err)
				return
			}
			file = f
		}

		if len(fc.Chunk) > 0 {
			if _, err := file.Write(fc.Chunk); err != nil {
				logger.Warnf("write file err: %v", err)
				file.Close()
				return
			}
		}
	}
}
