package main

import (
	"cpe-box/pb"
	"fmt"
	"log"
	"net"

	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"
)

func main() {
	listener, err := net.Listen("tcp", ":9999")
	if err != nil {
		log.Fatalf("Failed to listen on port 9999: %v", err)
	}
	defer listener.Close()

	fmt.Println("Server is listening on port 9999...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	log.Printf("New connection accepted from %s", conn.RemoteAddr())

	session, err := yamux.Server(conn, nil)
	if err != nil {
		log.Printf("Failed to create yamux server: %v", err)
		return
	}

	log.Printf("Session established with client")

	for {
		stream, err := session.Accept()
		if err != nil {
			log.Printf("Failed to accept stream: %v", err)
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream net.Conn) {
	defer stream.Close()

	buf := make([]byte, 1024)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if err.Error() == "EOF" {
				log.Printf("Stream closed by client")
				return
			}
			log.Printf("Failed to read from stream: %v", err)
			return
		}

		var msg pb.Message
		err = proto.Unmarshal(buf[:n], &msg)
		if err != nil {
			log.Printf("Failed to unmarshal protobuf message: %v", err)
			return
		}

		log.Printf("Received message from=%s body=%s", msg.From, msg.Body)

		reply := &pb.Message{
			From: "server",
			Body: "Hello, " + msg.From,
		}
		data, _ := proto.Marshal(reply)
		stream.Write(data)
	}
}
