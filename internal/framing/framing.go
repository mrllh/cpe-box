package framing

import (
	"encoding/binary"
	"io"
	"net"

	"google.golang.org/protobuf/proto"
)

func WriteMessage(conn net.Conn, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(data)))
	if _, err := conn.Write(lb[:]); err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

func ReadMessage(conn net.Conn, msg proto.Message) error {
	var lb [4]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(lb[:])
	if length == 0 {
		return io.EOF
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	return proto.Unmarshal(buf, msg)
}
