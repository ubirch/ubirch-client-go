package main

import (
	"fmt"
	"log"
	"math/rand"
)
import MQTT "github.com/eclipse/paho.mqtt.golang"

func mqtt(address string, user string, password string, handler MQTT.MessageHandler) (MQTT.Client, error) {
	opts := MQTT.NewClientOptions().AddBroker(address)
	opts.SetUsername(user)
	opts.SetUsername(password)
	opts.SetClientID(fmt.Sprintf("ubirch-mqtt-%d", rand.Uint32()))
	if handler != nil {
		opts.SetDefaultPublishHandler(handler)
	}
	topic := "/testLeo"

	opts.OnConnect = func(c MQTT.Client) {
		if token := c.Subscribe(topic, 0, handler); token.Wait() && token.Error() != nil {
			panic(token.Error())
		}
	}
	client := MQTT.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	} else {
		log.Printf("connected to mqtt server: %v", client)
	}
	return client, nil
}

/*
mqttHandler := func(client MQTT.Client, msg MQTT.Message) {
		data := msg.Payload()
		fmt.Printf("MSG: %s\n", hex.EncodeToString(data))

		verified, err := p.Verify("switch", data, ubirch.Chained)
		if err != nil {
			log.Printf("error verifying message: %v", err)
		}
		if !verified {
			log.Printf("message signature can't be verified")
		}

		raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:14001")
		if err != nil {
			return
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			return
		}
		//noinspection ALL
		defer conn.Close()

		n, err := io.Copy(conn, bytes.NewReader(data))
		if err != nil {
			log.Printf("can't write to UDP socket: %v", err)
		} else {
			log.Printf("sent %d bytes to UDP: %s", n, hex.EncodeToString(data))
		}
		log.Printf("sent command %s to UDP socket", hex.EncodeToString(data))

		//token := client.Publish("nn/result", 0, false, text)
		//token.Wait()
	}

	// set up mqtt client
	_, err = mqtt(conf.Mqtt.Address, conf.Mqtt.User, conf.Mqtt.Password, mqttHandler)
	if err != nil {
		log.Printf("mqtt client failed to start: %v", err)
	}
*/
