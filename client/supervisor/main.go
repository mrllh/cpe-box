package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var agentID string
var socketDir = "/tmp"

var (
	mu        sync.Mutex
	current   *exec.Cmd
	restartCh = make(chan struct{}, 1)
)

type Config struct {
	Agent struct {
		ID string `yaml:"id"`
	} `yaml:"agent"`
}

func main() {
	// flag.StringVar(&agentID, "id", "agent", "agent id")
	// flag.Parse()

	cfgPath := "../../config.yaml"
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Println("read config err:", err)
		return
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Println("parse config err:", err)
		return
	}
	agentID = cfg.Agent.ID
	if agentID == "" {
		agentID = "agent"
	}

	socketPath := fmt.Sprintf("%s/cpe_%s.sock", socketDir, agentID)
	_ = os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Println("listen uds err:", err)
		return
	}
	defer l.Close()
	fmt.Printf("supervisor for %s listening on %s\n", agentID, socketPath)

	go agentManager(socketPath)

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("accept uds err:", err)
			continue
		}
		go handleConn(conn)
	}
}

func agentManager(socketPath string) {
	retry := 0
	delay := time.Second
	for {
		fmt.Printf("starting agent %s attempt %d\n", agentID, retry+1)
		cmd := exec.Command("../agent/agent-cli", "--id", agentID)
		// cmd.Env = append(os.Environ(), fmt.Sprintf("CPE_AGENT_SOCK=%s", socketPath))
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("CPE_AGENT_SOCK=%s", socketPath),
			"AGENT_TLS=1",
			"AGENT_TLS_SKIP_VERIFY=1", // 测试用，生产请用 AGENT_TLS_CA
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		mu.Lock()
		current = cmd
		mu.Unlock()

		if err := cmd.Start(); err != nil {
			fmt.Println("start agent err:", err)
			return
		}

		waitCh := make(chan error, 1)
		go func() { waitCh <- cmd.Wait() }()

		select {
		case err := <-waitCh:
			fmt.Println("agent exited:", err)
			retry++
			if retry > 10 {
				fmt.Println("max retry exceeded")
				return
			}
			time.Sleep(delay)
			delay *= 2
		case <-restartCh:
			fmt.Println("kill for restart")
			_ = cmd.Process.Kill()
			<-waitCh
			fmt.Println("killed; restart now")
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
		fmt.Println("supervisor received:", msg)
		if msg == "restart" {
			select {
			case restartCh <- struct{}{}:
			default:
			}
		}
	}
}
