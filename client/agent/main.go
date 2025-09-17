package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"

	"cpe-box/pb"
)

const (
	serverAddr = "127.0.0.1:9999"
)

var udsPath = os.Getenv("CPE_AGENT_SOCK")

var agentID string

func main() {
	// 从命令行获取 ID
	flag.StringVar(&agentID, "id", "agent-123", "unique agent ID")
	flag.Parse()

	go connectSupervisor()
	connectServer()
}

func connectSupervisor() {
	for {
		conn, err := net.Dial("unix", udsPath)
		if err != nil {
			fmt.Println("Connect supervisor error:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		fmt.Println("Connected to supervisor")
		for {
			_, err = conn.Write([]byte(agentID + " alive\n"))
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
		log.Fatalf("Dial server error: %v", err)
	}
	defer conn.Close()

	session, err := yamux.Client(conn, nil)
	if err != nil {
		log.Fatalf("Yamux error: %v", err)
	}

	stream, err := session.Open()
	if err != nil {
		log.Fatalf("Open stream error: %v", err)
	}
	defer stream.Close()

	reg := &pb.Envelope{
		Payload: &pb.Envelope_Register{
			Register: &pb.Register{Id: agentID},
		},
	}
	data, _ := proto.Marshal(reg)
	stream.Write(data)
	log.Printf("Registered as %s", agentID)

	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		var env pb.Envelope
		if err := proto.Unmarshal(buf[:n], &env); err != nil {
			log.Printf("Unmarshal error: %v", err)
			continue
		}

		switch x := env.Payload.(type) {
		case *pb.Envelope_Command:
			handleCommand(x.Command)
		case *pb.Envelope_Message:
			handleMessage(x.Message)
		}
	}
}

func handleCommand(cmd *pb.Command) {
	fmt.Printf("[%s] Received command: %s (target=%s)\n", agentID, cmd.Action, cmd.TargetId)
	if cmd.Action == "RESTART" && cmd.TargetId == agentID {
		conn, err := net.Dial("unix", udsPath)
		if err != nil {
			fmt.Println("Cannot connect to supervisor:", err)
			return
		}
		defer conn.Close()
		conn.Write([]byte("restart"))
		fmt.Println("Sent restart request to supervisor")
		os.Exit(0)
	}
}

func handleMessage(msg *pb.Message) {
	fmt.Printf("[%s] Message from %s: %s\n", agentID, msg.From, msg.Body)
}
