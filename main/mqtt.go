package main

import (
	"fmt"
	"log"
	"math/rand"
)
import MQTT "github.com/eclipse/paho.mqtt.golang"

func mqtt(address string, user string, password string, handler MQTT.MessageHandler) error {
	opts := MQTT.NewClientOptions().AddBroker(address)
	opts.SetUsername(user)
	opts.SetUsername(password)
	opts.SetClientID(fmt.Sprintf("ubirch-mqtt-%d", rand.Uint32()))
	opts.SetDefaultPublishHandler(handler)
	topic := "/testLeo"

	opts.OnConnect = func(c MQTT.Client) {
		if token := c.Subscribe(topic, 0, handler); token.Wait() && token.Error() != nil {
			panic(token.Error())
		}
	}
	client := MQTT.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	} else {
		log.Printf("connected to mqtt server: %v", client)
	}
	return nil
}
