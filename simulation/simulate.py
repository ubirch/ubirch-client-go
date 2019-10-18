#! /usr/bin/env python3
import binascii
import re
import socket
import sys
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
input = "plc-a-data.txt"
interval = 30
if len(sys.argv) > 1:
    input = sys.argv[1]
if len(sys.argv) > 2:
    interval = int(sys.argv[2])

print(f"using {input} as input file, sending every {interval} seconds")
with open(input) as f:
    lines = f.readlines()
    for line in lines:
        m = re.match(r'^([0-9a-f]+).*', line, re.M | re.I)
        if m is not None:
            print(f"sending {m.group(1)}")
            sock.sendto(binascii.unhexlify(m.group(1)), ("localhost", 15001))
            time.sleep(interval)
