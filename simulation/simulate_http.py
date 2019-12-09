#! /usr/bin/env python3
import binascii
import re
import sys
import time

import requests

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
            r = requests.post(url="http://localhost:8080/sign", data=binascii.unhexlify(m.group(1)))
            print("{}: {}".format(r.status_code, r.content))
            time.sleep(interval)
