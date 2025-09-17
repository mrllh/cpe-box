package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

var (
	agentID   string
	socketDir = "/tmp"
)

const maxRetries = 10

var (
	mu        sync.Mutex
	current   *exec.Cmd
	restartCh = make(chan struct{}, 1)
)

func main() {
	flag.StringVar(&agentID, "id", "agent-123", "unique agent ID")
	flag.Parse()

	socketPath := fmt.Sprintf("%s/cpe_%s.sock", socketDir, agentID)
	_ = os.Remove(socketPath)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Println("Listen UDS error:", err)
		return
	}
	defer l.Close()
	fmt.Printf("Supervisor for %s listening on %s\n", agentID, socketPath)

	go agentManager(socketPath)

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Accept error:", err)
			continue
		}
		go handleConn(conn)
	}
}

func agentManager(socketPath string) {
	retry := 0
	delay := time.Second

	for {
		fmt.Printf("Starting agent %s, attempt %d...\n", agentID, retry+1)
		cmd := exec.Command("../agent/agent-cli", "--id", agentID)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("CPE_AGENT_SOCK=%s", socketPath)) // 传给 agent 用哪个 UDS

		mu.Lock()
		current = cmd
		mu.Unlock()

		err := cmd.Start()
		if err != nil {
			fmt.Println("Failed to start agent:", err)
			return
		}

		waitDone := make(chan error, 1)
		go func() { waitDone <- cmd.Wait() }()

		select {
		case err := <-waitDone:
			fmt.Printf("Agent %s exited: %v\n", agentID, err)
			retry++
			if retry >= maxRetries {
				fmt.Printf("Max retries reached for %s, stopping\n", agentID)
				return
			}
			time.Sleep(delay)
			delay *= 2
		case <-restartCh:
			fmt.Printf("Supervisor: restart requested for %s, killing agent...\n", agentID)
			_ = cmd.Process.Kill()
			<-waitDone
			fmt.Printf("Agent %s killed; restarting immediately\n", agentID)
			retry = 0
			delay = time.Second
		}
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		msg := string(buf[:n])
		fmt.Printf("Supervisor[%s] received: %s\n", agentID, msg)

		if msg == "restart" {
			select {
			case restartCh <- struct{}{}:
			default:
			}
		}
	}
}
