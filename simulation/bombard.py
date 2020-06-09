import binascii
import hashlib
import json
import secrets
import sys
import time

import msgpack
import requests

if len(sys.argv) < 3:
    print("usage:")
    print("python3 ./bombard.py <UUID> <AUTH_TOKEN>")
    sys.exit()

num = 10
uuid = sys.argv[1]
auth = sys.argv[2]

data_json_type = "JSON data"
data_bin_type = "binary data"
hash_bin_type = "binary hash"
hash_b64_type = "base64 hash"

types = [data_json_type, data_bin_type, hash_bin_type, hash_b64_type]

base_url = 'http://localhost:8080'
sign_data_url = base_url + '/{}'.format(uuid)
sign_hash_url = base_url + '/{}/hash'.format(uuid)
vrfy_data_url = base_url + '/verify'
vrfy_hash_url = base_url + '/verify/hash'

auth_header = {'X-Auth-Token': auth}
bin_header = {'Content-Type': 'application/octet-stream'}
txt_header = {'Content-Type': 'text/plain'}
json_header = {'Content-Type': 'application/json'}

letters = ("a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F", "ä", "ö", "ü", "Ä", "Ö", "Ü")
hashes = []  # [(msg, hash, upp)]
failed = {}
max_dur = 0


def hash_msg(msg: dict) -> (bytes, str):
    serialized = json.dumps(msg, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
    msg_hash = hashlib.sha256(serialized).digest()
    return serialized, binascii.b2a_base64(msg_hash).decode().rstrip('\n')


# generates random JSON message and returns msg_str, serialized, msg_hash
def get_message() -> (dict, bytes, str):
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
    serialized, msg_hash = hash_msg(msg)
    return msg, serialized, msg_hash


def send_request(url: str, headers: dict, data: str or bytes) -> requests.Response:
    global max_dur
    start_time = int(time.time())
    r = requests.post(url=url, headers=headers, data=data)
    dur = int(time.time()) - start_time
    if dur > max_dur: max_dur = dur
    return r


def check_signing_response(r: requests.Response, request_type: str, msg: dict, serialized: bytes, hash: str) -> bool:
    try:
        r_map = json.loads(r.text)
    except Exception:
        print("client returned error: ({}) {}".format(r.status_code, r.text))
        return False

    if r.status_code != 200:
        print("{} signing request failed! {}: ".format(request_type, r.status_code))
        print(msgpack.unpackb(binascii.a2b_base64(r_map["response"]), raw=False)[-2])
        return False
    else:
        if r_map["hash"] != hash:
            print(" - - - HASH MISMATCH ! - - - ")
            print("sorted compact json (py): {}".format(serialized.decode()))
            print("hash (go): {}".format(r_map["hash"]))
            print("hash (py): {}".format(hash))
            return False

    hashes.append((msg, hash, r_map["upp"]))  # [(msg, hash, upp)]
    return True


def send_signing_request(request_type: str):
    msg, serialized, hash = get_message()

    if request_type == data_json_type:
        url, header, data = sign_data_url, json_header, json.dumps(msg)
    if request_type == data_bin_type:
        url, header, data = sign_data_url, bin_header, serialized
    if request_type == hash_bin_type:
        url, header, data = sign_hash_url, bin_header, binascii.a2b_base64(hash)
    if request_type == hash_b64_type:
        url, header, data = sign_hash_url, txt_header, hash

    r = send_request(url=url, headers={**auth_header, **header}, data=data)
    if not check_signing_response(r, request_type, msg, serialized, hash):
        failed[request_type] += 1


def check_verification_response(r: requests.Response, request_type: str, msg: dict, hash: str, upp: str) -> bool:
    if r.status_code != 200:
        print("NOT VERIFIED: ({})".format(request_type))
        print("json: {}".format(repr(msg)))
        print("hash: {}".format(hash))
        print("response: ({}) {}".format(r.status_code, r.text))
        return False
    else:
        r_map = json.loads(r.text)

        if upp != r_map["upp"]:
            print(" - - - UPP MISMATCH ! - - - ")
            print("UPP from signing resp.: {}".format(upp))
            print("UPP from verification resp.: {}".format(r_map["upp"]))
            return False

    return True


def send_verification_request(request_type: str, msg: dict, hash: str, upp: str):
    if request_type == data_json_type:
        url, header, data = vrfy_data_url, json_header, json.dumps(msg)
    if request_type == data_bin_type:
        url, header, data = vrfy_data_url, bin_header, json.dumps(msg, separators=(',', ':'), sort_keys=True,
                                                                  ensure_ascii=False).encode()
    if request_type == hash_bin_type:
        url, header, data = vrfy_hash_url, bin_header, binascii.a2b_base64(hash)
    if request_type == hash_b64_type:
        url, header, data = vrfy_hash_url, txt_header, hash

    r = send_request(url=url, headers=header, data=data)
    if not check_verification_response(r, request_type, msg, hash, upp):
        failed[request_type] += 1


print("\nsigning {} messages...".format(num * len(types)))
i = 0
for t in types:
    failed[t] = 0
while i < num:
    i += 1

    for t in types:
        send_signing_request(t)

    if i % 10 == 0 and i != 0:
        for t in types:
            print("{} of {} {} signing requests failed.".format(failed[t], i, t))

print(" max. signing duration: {} sec".format(max_dur))
max_dur = 0

print("\nverifying {} hashes...".format(len(hashes)))
i = 0
for t in types:
    failed[t] = 0
for msg, hash, upp in hashes:
    i += 1

    for t in types:
        send_verification_request(t, msg, hash, upp)

    if i % 10 == 0:
        for t in types:
            print("{} of {} {} verification requests failed.".format(failed[t], i, t))

print(" max. verification duration: {} sec".format(max_dur))
