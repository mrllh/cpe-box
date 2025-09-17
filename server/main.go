package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"

	"cpe-box/pb"
)

var (
	mu     sync.Mutex
	agents = make(map[string]net.Conn) // agentID -> stream
)

func main() {
	listener, err := net.Listen("tcp", ":9999")
	if err != nil {
		log.Fatalf("Listen error: %v", err)
	}
	defer listener.Close()

	fmt.Println("Server listening on :9999")

	// 接收 agent 连接
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			go handleConn(conn)
		}
	}()

	console()
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	session, err := yamux.Server(conn, nil)
	if err != nil {
		log.Printf("Yamux error: %v", err)
		return
	}

	for {
		stream, err := session.Accept()
		if err != nil {
			log.Printf("Accept stream error: %v", err)
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream net.Conn) {
	defer stream.Close()

	for {
		buf := make([]byte, 4096)
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Stream closed: %v", err)
			return
		}

		var env pb.Envelope
		if err := proto.Unmarshal(buf[:n], &env); err != nil {
			log.Printf("Unmarshal error: %v", err)
			continue
		}

		switch x := env.Payload.(type) {
		case *pb.Envelope_Register:
			id := x.Register.Id
			mu.Lock()
			agents[id] = stream
			mu.Unlock()
			log.Printf("Agent registered: %s", id)

		case *pb.Envelope_Message:
			log.Printf("Message from %s: %s", x.Message.From, x.Message.Body)

		default:
			log.Printf("Unknown payload")
		}
	}
}

func console() {
	scanner := bufio.NewScanner(os.Stdin)
	printHelp()

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 3)

		switch parts[0] {
		case "list":
			listAgents()
		case "restart":
			if len(parts) < 2 {
				fmt.Println("Usage: restart <agent-id>")
				continue
			}
			sendCommand(parts[1], "RESTART")
		case "msg":
			if len(parts) < 3 {
				fmt.Println("Usage: msg <agent-id> <text>")
				continue
			}
			sendMessage(parts[1], parts[2])
		case "help":
			printHelp()
		default:
			fmt.Println("Unknown command. Type 'help' for usage.")
		}
	}
}

func listAgents() {
	mu.Lock()
	defer mu.Unlock()
	if len(agents) == 0 {
		fmt.Println("No agents connected.")
		return
	}
	fmt.Println("Connected agents:")
	for id := range agents {
		fmt.Println(" -", id)
	}
}

func sendCommand(agentID, action string) {
	mu.Lock()
	stream, ok := agents[agentID]
	mu.Unlock()

	if !ok {
		fmt.Println("No such agent:", agentID)
		return
	}

	env := &pb.Envelope{
		Payload: &pb.Envelope_Command{
			Command: &pb.Command{
				TargetId: agentID,
				Action:   action,
			},
		},
	}
	data, _ := proto.Marshal(env)
	_, err := stream.Write(data)
	if err != nil {
		log.Printf("Send command error: %v", err)
	} else {
		fmt.Printf("Sent %s to %s\n", action, agentID)
	}
}

func sendMessage(agentID, text string) {
	mu.Lock()
	stream, ok := agents[agentID]
	mu.Unlock()

	if !ok {
		fmt.Println("No such agent:", agentID)
		return
	}

	env := &pb.Envelope{
		Payload: &pb.Envelope_Message{
			Message: &pb.Message{
				From: "server",
				Body: text,
			},
		},
	}
	data, _ := proto.Marshal(env)
	_, err := stream.Write(data)
	if err != nil {
		log.Printf("Send message error: %v", err)
	} else {
		fmt.Printf("Sent message to %s: %s\n", agentID, text)
	}
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  list                - List all connected agents")
	fmt.Println("  restart <agent-id>  - Restart a specific agent")
	fmt.Println("  msg <agent-id> text - Send a text message to agent")
	fmt.Println("  help                - Show this help")
}
