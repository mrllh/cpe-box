package main

import (
	"cpe-box/pb"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"
)

const (
	udsPath    = "/tmp/cpe_agent.sock"
	serverAddr = "127.0.0.1:9999"
)

func main() {
	go connectSupervisor()

	connectServer()
}

func connectSupervisor() {
	for {
		conn, err := net.Dial("unix", udsPath)
		if err != nil {
			fmt.Println("Failed to connect to supervisor:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		fmt.Println("Connected to supervisor")

		for {
			_, err = conn.Write([]byte("agent-cli alive"))
			if err != nil {
				fmt.Println("Write to supervisor error:", err)
				break
			}
			time.Sleep(5 * time.Second)
		}
		conn.Close()
	}
}

func connectServer() {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Println("Failed to connect to server:", err)
		return
	}
	defer conn.Close()

	session, err := yamux.Client(conn, nil)
	if err != nil {
		fmt.Println("Failed to create yamux session:", err)
	}

	stream, err := session.Open()
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}

	for {
		msg := &pb.Message{
			From: "agent-cli",
			Body: "Hello server",
		}
		data, _ := proto.Marshal(msg)
		_, err := stream.Write(data)
		if err != nil {
			log.Fatalf("Failed to write to stream: %v", err)
		}

		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			log.Fatalf("Failed to read from stream: %v", err)
		}
		var reply pb.Message
		_ = proto.Unmarshal(buf[:n], &reply)
		fmt.Printf("Received from server: from=%s body=%s\n", reply.From, reply.Body)

		time.Sleep(5 * time.Second)
	}

}
