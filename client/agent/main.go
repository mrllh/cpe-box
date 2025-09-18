package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
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

var (
	ctrlStreamMu sync.Mutex
	ctrlStream   net.Conn
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

	ctrlStreamMu.Lock()
	ctrlStream = stream
	ctrlStreamMu.Unlock()
	defer func() {
		ctrlStreamMu.Lock()
		if ctrlStream != nil {
			_ = ctrlStream.Close()
			ctrlStream = nil
		}
		ctrlStreamMu.Unlock()
	}()

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
		go handleIncomingStream(stream)
	}
}

func handleIncomingStream(stream net.Conn) {
	defer stream.Close()

	// Read first framed envelope to know stream type
	var env pb.Envelope
	if err := framing.ReadMessage(stream, &env); err != nil {
		if err == io.EOF {
			logger.Infof("incoming stream closed")
		} else {
			logger.Warnf("failed to read initial envelope on stream: %v", err)
		}
		return
	}

	switch x := env.Payload.(type) {
	case *pb.Envelope_FileChunk:
		// This stream is a file transfer: handle remaining file chunks in framing mode
		handleFileStreamFramed(stream, x.FileChunk)
		return

	case *pb.Envelope_PortForward:
		// This stream is port forward: x.PortForward.TargetAddr is agent-local target
		target := x.PortForward.TargetAddr
		// Dial local target on agent
		localConn, err := net.Dial("tcp", target)
		if err != nil {
			logger.Warnf("port-forward dial local %s err: %v", target, err)
			return
		}
		// After we consumed the initial framed metadata, switch to raw io.Copy between stream and localConn
		done := make(chan struct{}, 2)
		go func() {
			_, err := io.Copy(localConn, stream)
			if err != nil {
				logger.Warnf("io.Copy stream->local err: %v", err)
			}
			localConn.Close()
			done <- struct{}{}
		}()
		go func() {
			_, err := io.Copy(stream, localConn)
			if err != nil {
				logger.Warnf("io.Copy local->stream err: %v", err)
			}
			done <- struct{}{}
		}()
		<-done
		localConn.Close()
		return

	default:
		logger.Warnf("unexpected initial envelope on stream")
		return
	}
}

func handleFileStreamFramed(stream net.Conn, first *pb.FileChunk) {
	// first is meta (may have Chunk==nil)
	transferID := first.TransferId
	filename := first.Filename
	expectedSize := first.TotalSize
	expectedSha := first.Sha256

	path := filepath.Join("/tmp", transferID+"_"+filename)
	logger.Infof("Receiving file transfer %s -> %s expected_size=%d sha256=%s", transferID, path, expectedSize, expectedSha)

	// create file (truncate if exists)
	f, err := os.Create(path)
	if err != nil {
		logger.Warnf("create file err: %v", err)
		return
	}
	defer f.Close()

	// set up sha256 calculator
	h := sha256.New()
	received := int64(0)
	chunkIdx := 0

	// If first chunk had bytes (unlikely for meta), write them
	if len(first.Chunk) > 0 {
		if _, err := f.Write(first.Chunk); err != nil {
			logger.Warnf("write initial chunk err: %v", err)
			return
		}
		if _, err := h.Write(first.Chunk); err != nil {
			logger.Warnf("hash write err: %v", err)
			return
		}
		received += int64(len(first.Chunk))
		chunkIdx++
		logger.Infof("Received initial chunk #%d size=%d transfer=%s progress=%d/%d", chunkIdx, len(first.Chunk), transferID, received, expectedSize)
	}

	// read remaining framed FileChunk messages until Last==true
	for {
		var env pb.Envelope
		if err := framing.ReadMessage(stream, &env); err != nil {
			if err == io.EOF {
				logger.Infof("file stream closed for transfer %s", transferID)
			} else {
				logger.Warnf("read chunk err: %v", err)
			}
			break
		}
		fch, ok := env.Payload.(*pb.Envelope_FileChunk)
		if !ok {
			logger.Warnf("expected FileChunk on file stream for transfer %s", transferID)
			continue
		}
		fc := fch.FileChunk
		if fc.Last {
			logger.Infof("Received last marker for transfer %s", transferID)
			break
		}
		if len(fc.Chunk) > 0 {
			n, err := f.Write(fc.Chunk)
			if err != nil || n != len(fc.Chunk) {
				logger.Warnf("write file err: %v", err)
				return
			}
			if _, err := h.Write(fc.Chunk); err != nil {
				logger.Warnf("hash write err: %v", err)
				return
			}
			received += int64(len(fc.Chunk))
			chunkIdx++
			// print per chunk
			logger.Infof("Received chunk #%d size=%d transfer=%s progress=%d/%d", chunkIdx, len(fc.Chunk), transferID, received, expectedSize)
		}
	}

	// final verification
	// final verification (after computing calcHex and received)
	calcSum := h.Sum(nil)
	calcHex := hex.EncodeToString(calcSum)
	ok := false
	if expectedSha != "" {
		if calcHex == expectedSha && (expectedSize == 0 || received == expectedSize) {
			logger.Infof("File transfer successful: %s size=%d sha256 match=%s", path, received, calcHex)
			ok = true
		} else {
			logger.Warnf("File transfer verification FAILED for %s: expected size=%d got=%d, expected sha=%s got=%s",
				path, expectedSize, received, expectedSha, calcHex)
			ok = false
		}
	} else {
		logger.Infof("File transfer finished (no hash provided): %s received=%d sha256=%s", path, received, calcHex)
		ok = (expectedSize == 0 || received == expectedSize)
	}

	// send status back to server via control stream
	note := ""
	if !ok {
		note = "verification failed"
	}
	if err := reportFileTransferStatus(transferID, ok, received, expectedSize, calcHex, note); err != nil {
		logger.Warnf("failed to report transfer status to server: %v", err)
	}

}

func reportFileTransferStatus(transferID string, ok bool, received int64, expected int64, sha256hex string, note string) error {
	// build JSON body
	body := map[string]interface{}{
		"type":        "file_transfer_result",
		"transfer_id": transferID,
		"ok":          ok,
		"received":    received,
		"expected":    expected,
		"sha256":      sha256hex,
		"note":        note,
		"timestamp":   time.Now().Unix(),
	}
	bs, _ := json.Marshal(body)
	env := &pb.Envelope{Payload: &pb.Envelope_Message{Message: &pb.Message{From: "agent", Body: string(bs)}}}

	ctrlStreamMu.Lock()
	defer ctrlStreamMu.Unlock()
	if ctrlStream == nil {
		// no control stream available
		return fmt.Errorf("no control stream to server")
	}
	if err := framing.WriteMessage(ctrlStream, env); err != nil {
		return fmt.Errorf("failed to send file transfer status: %w", err)
	}
	logger.Infof("reported transfer %s status ok=%v to server", transferID, ok)
	return nil
}
