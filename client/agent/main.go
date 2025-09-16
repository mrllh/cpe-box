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
	log.Printf("Connecting to server at %s", serverAddr)
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Printf("Failed to connect to server: %v", err)
		return
	}
	defer conn.Close()

	session, err := yamux.Client(conn, nil)
	if err != nil {
		log.Printf("Failed to create yamux session: %v", err)
		return
	}
	log.Printf("Session established with server")

	for {
		stream, err := session.Open()
		if err != nil {
			log.Printf("Failed to open stream: %v", err)
			break
		}

		go func(stream net.Conn) {
			defer stream.Close()

			for {
				msg := &pb.Message{
					From: "agent-cli",
					Body: "Hello server",
				}
				data, err := proto.Marshal(msg)
				if err != nil {
					log.Printf("Failed to marshal message: %v", err)
					return
				}

				_, err = stream.Write(data)
				if err != nil {
					log.Printf("Failed to write to stream: %v", err)
					return
				}

				buf := make([]byte, 1024)
				n, err := stream.Read(buf)
				if err != nil {
					if err.Error() == "EOF" {
						log.Printf("Stream closed by server")
						return
					}
					log.Printf("Failed to read from stream: %v", err)
					return
				}

				var reply pb.Message
				err = proto.Unmarshal(buf[:n], &reply)
				if err != nil {
					log.Printf("Failed to unmarshal reply: %v", err)
					return
				}
				log.Printf("Received from server: from=%s body=%s", reply.From, reply.Body)

				time.Sleep(5 * time.Second)
			}
		}(stream)
	}
}
