package main

import (
	"log"
	"net"
	"strconv"
)

type UDPMessage struct {
	addr *net.UDPAddr
	data []byte
}

type UDPServer struct {
	handler chan UDPMessage
}

//noinspection GoUnhandledErrorResult
func (srv *UDPServer) Listen(addr string, port int) error {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr+":"+strconv.Itoa(port))
	if err != nil {
		return err
	}

	// setup listener for incoming UDP connection
	listener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("UDP server up and listening on %v", udpAddr)

	for {
		buffer := make([]byte, 1024)

		// wait for UDP packats
		n, addr, err := listener.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("error reading udp: %v", err)
			return err
		}

		// handle message asynchronously, just warn if handling failed
		srv.handler <- UDPMessage{addr, buffer[:n]}
	}
}
