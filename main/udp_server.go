package main

import (
	"context"
	"log"
	"net"
	"strconv"
	"sync"
)

type UDPMessage struct {
	addr *net.UDPAddr
	data []byte
}

type UDPServer struct {
	handler chan UDPMessage
}

//noinspection GoUnhandledErrorResult
func (srv *UDPServer) Listen(addr string, port int, ctx context.Context, wg *sync.WaitGroup) error {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr+":"+strconv.Itoa(port))
	if err != nil {
		return err
	}

	// setup listener for incoming UDP connection
	listener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	go func() {
		defer wg.Done()

		for {
			buffer := make([]byte, 1024)

			// wait for UDP packats
			n, addr, err := listener.ReadFromUDP(buffer)
			if err != nil {
				log.Printf("error reading udp: %v, stopping UDP server", err)
				return
			}

			// handle message asynchronously, just warn if handling failed
			srv.handler <- UDPMessage{addr, buffer[:n]}
		}
	}()

	log.Printf("UDP server up and listening on %v", udpAddr)

	return nil
}
