/*
 * Copyright (c) 2019 ubirch GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
)

type UDPServer struct {
	receiveHandler  chan []byte
	responseHandler chan []byte
}

func (srv *UDPServer) Listen(addr string, ctx context.Context, wg *sync.WaitGroup) error {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
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
			log.Printf("UDP client received message from %v: %s\n", addr, hex.EncodeToString(buffer[:n]))

			// handle message asynchronously, just warn if handling failed
			srv.receiveHandler <- buffer[:n]
		}
	}()

	log.Printf("UDP server up and listening on %v", udpAddr)

	return nil
}

func (srv *UDPServer) Serve(addr string, ctx context.Context, wg *sync.WaitGroup) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	connection, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		panic(fmt.Sprintf("network error setting up response sender: %v", err))
	}

	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-srv.responseHandler:
				_, err := connection.Write(msg)
				if err != nil {
					log.Printf("can't send response: %02x", msg[len(msg)-1])
				} else {
					log.Printf("sent UDP response: %02x", msg[len(msg)-1])
				}
			case <-ctx.Done():
				connection.Close()
				return
			}
		}
	}()

	log.Printf("sending verification results to: %s", udpAddr.String())

	return nil
}
