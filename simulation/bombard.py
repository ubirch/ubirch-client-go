import base64
import hashlib
import json
import secrets
import sys
import time

import requests


def hash_msg(msg: dict) -> (str, str):
    serialized = json.dumps(msg, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
    msg_hash = hashlib.sha256(serialized).digest()
    return serialized.decode(), base64.b64encode(msg_hash).decode().rstrip('\n')


if len(sys.argv) < 3:
    print("usage:")
    print("python3 ./bombard.py <UUID> <AUTH_TOKEN>")
    sys.exit()

env = "demo"
uuid = sys.argv[1]
auth = sys.argv[2]
url = 'http://localhost:8080/{}'.format(uuid)
headers = {
    'Content-Type': 'application/json',
    'X-Auth-Token': auth,
}
hashes = []
max_dur = 0
i, failed = 0, 0
letters = ("a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F", "ä", "ö", "ü", "Ä", "Ö", "Ü")
while i < 100:
    i += 1

    # create message to sign
    msg = {
        "id": uuid,
        "ts": int(time.time()),
        "big": secrets.randbits(53),
        "tpl": (secrets.randbits(32), secrets.randbits(8), secrets.randbits(16), secrets.randbits(4)),
        "lst": [
            secrets.choice(letters),
            secrets.choice(letters),
            secrets.choice(letters),
            secrets.choice(letters)
        ],
        "map": {
            secrets.choice(letters): secrets.randbits(4),
            secrets.choice(letters): secrets.randbits(16),
            secrets.choice(letters): secrets.randbits(8),
            secrets.choice(letters): secrets.randbits(32)
        }
    }
    msg_str = json.dumps(msg)
    serialized, msg_hash = hash_msg(msg)

    # print(msg_str)
    # print(msg_hash)
    # print()

    # send request
    start_time = int(time.time())
    r = requests.post(url=url, headers=headers, data=msg_str)
    dur = int(time.time()) - start_time
    if dur > max_dur: max_dur = dur

    if r.status_code != 200:
        print("request failed! {}: {}".format(r.status_code, r.text))
        failed += 1
    else:
        r_map = json.loads(r.content)
        if r_map["hash"] != msg_hash:
            print(" - - - FATAL: HASH MISMATCH ! - - - ")
            print("compact sorted json (py): {}".format(serialized))
            print("hash (go): {}".format(r_map["hash"]))
            print("hash (py): {}".format(msg_hash))
        else:
            hashes.append(msg_hash)

    if i % 10 == 0 and i != 0:
        print("{} of {} requests failed.".format(failed, i))
        print("   max. duration:        {} sec".format(max_dur))
        max_dur = 0

# wait before verifying
time.sleep(2)

url = "https://verify.{}.ubirch.com/api/upp/verify".format(env)
headers = {
    'Accept': 'application/json',
    'Content-Type': 'text/plain'
}
not_verified = 0
for hash in hashes:
    r = requests.post(url=url, headers=headers, data=hash)
    if r.status_code != 200:
        print("NOT VERIFIED: " + hash)
        print("response: {}: {}".format(r.status_code, r.text))
        not_verified += 1

print("{} of {} verifications failed.".format(not_verified, len(hashes)))
