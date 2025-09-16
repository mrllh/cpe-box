package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

const (
	socketPath = "/tmp/cpe_agent.sock"
	maxRetries = 10
)

func main() {
	_ = os.Remove(socketPath)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Println("Listen UDS error:", err)
	}
	defer l.Close()
	fmt.Println("Supervisor is listening on, waiting for agent to connect...")

	go startAgent()

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Accept error:", err)
			continue
		}
		go handleConn(conn)
	}
}

func startAgent() {
	retry := 0
	delay := time.Second

	for retry < maxRetries {
		fmt.Printf("Starting agent, attempt %d...\n", retry+1)

		cmd := exec.Command("../agent/agent-cli")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Start()
		if err != nil {
			fmt.Println("Failed to start agent:", err)
			return
		}

		err = cmd.Wait()
		fmt.Println("Agent process exited:", err)

		retry++
		time.Sleep(delay)
		delay *= 2
	}

	fmt.Println("Max retries reached. Giving up on starting agent.")
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 1024)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Read error:", err)
			return
		}
		msg := string(buf[:n])
		fmt.Println("Received from agent:", msg)

		conn.Write([]byte("ok"))
	}
}
