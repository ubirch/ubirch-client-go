#! /usr/bin/env python3
import time

import paho.mqtt.client as mqtt

connected = False

def sender(client, userdata, flags, rc):
    global connected
    print("client connected ...")
    connected = True


client = mqtt.Client("switch-sim")
client.on_connect = sender

client.connect("test.mosquitto.org", port=1883, keepalive=60, bind_address="")
client.loop_start()

while True:
    while not connected:
        time.sleep(1)

    print("client sending ...")
    client.publish("/testLeo", bytes([0x01]))
    time.sleep(20)
    client.publish("/testLeo", bytes([0x00]))
    time.sleep(20)
