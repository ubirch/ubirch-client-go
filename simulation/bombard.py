import base64
import binascii
import hashlib
import json
import secrets
import sys
import time

import msgpack
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

base_url = 'http://localhost:8080'
sign_json_url = base_url + '/{}'.format(uuid)
sign_hash_url = base_url + '/{}/hash'.format(uuid)
vrfy_json_url = base_url + '/verify'.format(uuid)
vrfy_hash_url = base_url + '/verify/hash'.format(uuid)

auth_header = {'X-Auth-Token': auth}
hash_header = {'Content-Type': 'application/octet-stream'}
json_header = {'Content-Type': 'application/json'}

hashes = []
max_dur = 0
i, failed = 0, 0
letters = ("a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F", "ä", "ö", "ü", "Ä", "Ö", "Ü")

while i < 10:
    i += 1

    # create message to sign
    msg = {
        "id": uuid,
        "ts": int(time.time()),
        "big": secrets.randbits(53),
        # "tpl": (secrets.randbits(32), secrets.randbits(8), secrets.randbits(16), secrets.randbits(4)),
        # "lst": [
        #     secrets.choice(letters),
        #     secrets.choice(letters),
        #     secrets.choice(letters),
        #     secrets.choice(letters)
        # ],
        # "map": {
        #     secrets.choice(letters): secrets.randbits(4),
        #     secrets.choice(letters): secrets.randbits(16),
        #     secrets.choice(letters): secrets.randbits(8),
        #     secrets.choice(letters): secrets.randbits(32)
        # }
    }
    msg_str = json.dumps(msg)
    serialized, msg_hash = hash_msg(msg)

    # print(msg_str)
    # print(msg_hash)
    # print()

    # send request
    start_time = int(time.time())
    r = requests.post(url=sign_json_url,
                      headers={**auth_header, **json_header},
                      data=msg_str)
    dur = int(time.time()) - start_time
    if dur > max_dur: max_dur = dur

    try:
        r_map = json.loads(r.text)
    except Exception:
        print("client returned error: ({}) {}".format(r.status_code, r.text))
        continue

    if r.status_code != 200:
        print("request failed! {}: ".format(r.status_code))
        resp_msg = msgpack.unpackb(binascii.a2b_base64(r_map["response"]), raw=False)[-2]
        print(resp_msg)
        failed += 1
    else:
        if r_map["hash"] != msg_hash:
            print(" - - - HASH MISMATCH ! - - - ")
            print("compact sorted json (py): {}".format(serialized))
            print("hash (go): {}".format(r_map["hash"]))
            print("hash (py): {}".format(msg_hash))
        else:
            hashes.append(binascii.a2b_base64(msg_hash))

    if i % 10 == 0 and i != 0:
        print("{} of {} requests failed.".format(failed, i))
        print("          max. duration: {} sec".format(max_dur))
        max_dur = 0

i = 0
while len(hashes) > 0:
    i += 1
    print("\nverifying {} hashes...".format(len(hashes)))
    for hash in hashes:
        r = requests.post(url=vrfy_hash_url, headers=hash_header, data=hash)
        if r.status_code != 200:
            print("NOT VERIFIED: " + binascii.b2a_base64(hash).decode())
            print("response: ({}) {}".format(r.status_code, r.text))
        else:
            hashes.remove(hash)
    print("\n{} verifications failed on {}. try.\n".format(len(hashes), i))
