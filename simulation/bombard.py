import binascii
import hashlib
import json
import secrets
import sys
import time

import msgpack
import requests

letters = ("a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F", "ä", "ö", "ü", "Ä", "Ö", "Ü")

json_type = "JSON data package"
hash_bin_type = "binary hash"
hash_b64_type = "base64 hash"

hashes = []
max_dur = 0


def hash_msg(msg: dict) -> (str, str):
    serialized = json.dumps(msg, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
    msg_hash = hashlib.sha256(serialized).digest()
    return serialized.decode(), binascii.b2a_base64(msg_hash).decode().rstrip('\n')


# generates random JSON message and returns msg_str, serialized, msg_hash
def get_message() -> (str, str, str):
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
    return msg_str, serialized, msg_hash


def send_request(url: str, headers: dict, data: str or bytes) -> requests.Response:
    global max_dur
    start_time = int(time.time())
    r = requests.post(url=url, headers=headers, data=data)
    dur = int(time.time()) - start_time
    if dur > max_dur: max_dur = dur
    return r


def check_response(r: requests.Response, request_kind: str, msg_str: str, serialized: str, msg_hash: str) -> bool:
    try:
        r_map = json.loads(r.text)
    except Exception:
        print("client returned error: ({}) {}".format(r.status_code, r.text))
        return False

    if r.status_code != 200:
        print("{} signing request failed! {}: ".format(request_kind, r.status_code))
        print(msgpack.unpackb(binascii.a2b_base64(r_map["response"]), raw=False)[-2])
        return False
    else:
        if r_map["hash"] != msg_hash:
            print(" - - - HASH MISMATCH ! - - - ")
            print("compact sorted json (py): {}".format(serialized))
            print("hash (go): {}".format(r_map["hash"]))
            print("hash (py): {}".format(msg_hash))
            return False
        else:
            hashes.append((msg_str, binascii.a2b_base64(msg_hash)))
            return True


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
hash_bin_header = {'Content-Type': 'application/octet-stream'}
hash_txt_header = {'Content-Type': 'text/plain'}
json_header = {'Content-Type': 'application/json'}

i, failed, failed[json_type], failed[hash_bin_type], failed[hash_b64_type] = 0, {}, 0, 0, 0
while i < 1:
    i += 1

    # sign JSON
    msg_str, serialized, msg_hash = get_message()
    r = send_request(url=sign_json_url,
                     headers={**auth_header, **json_header},
                     data=msg_str)
    if not check_response(r, json_type, msg_str, serialized, msg_hash):
        failed[json_type] += 1

    # sign hash (binary)
    (msg_str, serialized, msg_hash) = get_message()
    r = send_request(url=sign_hash_url,
                     headers={**auth_header, **hash_bin_header},
                     data=binascii.a2b_base64(msg_hash))
    if not check_response(r, hash_bin_type, msg_str, serialized, msg_hash):
        failed[hash_bin_type] += 1

    # sign hash (base64)
    msg_str, serialized, msg_hash = get_message()
    r = send_request(url=sign_hash_url,
                     headers={**auth_header, **hash_txt_header},
                     data=msg_hash)
    if not check_response(r, hash_b64_type, msg_str, serialized, msg_hash):
        failed[hash_b64_type] += 1

    if i % 10 == 0 and i != 0:
        print("{} of {} {} signing requests failed.".format(failed[json_type], i, json_type))
        print("{} of {} {} signing requests failed.".format(failed[hash_bin_type], i, hash_bin_type))
        print("{} of {} {} signing requests failed.".format(failed[hash_b64_type], i, hash_b64_type))
        print(" max. duration: {} sec".format(max_dur))
        max_dur = 0

unverified_hashes = []
unverified_json_msgs = []
i, failed[json_type], failed[hash_bin_type], failed[hash_b64_type] = 0, 0, 0, 0
print("\nverifying {} hashes...".format(len(hashes)))
for msg, hash in hashes:
    i += 1

    # verify JSON
    r = send_request(url=vrfy_json_url,
                     headers=json_header,
                     data=msg)

    if r.status_code != 200:
        print("NOT VERIFIED: {} ({})".format(msg, json_type))
        print("response: ({}) {}".format(r.status_code, r.text))
        unverified_json_msgs.append(msg)
        failed[json_type] += 1

    # verify hash (binary)
    r = send_request(url=vrfy_hash_url,
                     headers=hash_bin_header,
                     data=hash)

    if r.status_code != 200:
        print("NOT VERIFIED: {} ({})".format(binascii.b2a_base64(hash).decode(), hash_bin_type))
        print("response: ({}) {}".format(r.status_code, r.text))
        unverified_hashes.append(hash)
        failed[hash_bin_type] += 1

    # verify hash (base64)
    r = send_request(url=vrfy_hash_url,
                     headers=hash_txt_header,
                     data=binascii.b2a_base64(hash).decode().rstrip('\n'))

    if r.status_code != 200:
        print("NOT VERIFIED: {} ({})".format(binascii.b2a_base64(hash).decode(), hash_b64_type))
        print("response: ({}) {}".format(r.status_code, r.text))
        unverified_hashes.append(hash)
        failed[hash_b64_type] += 1

    if i % 10 == 0:
        print("{} of {} {} verification requests failed.".format(failed[json_type], i, json_type))
        print("{} of {} {} verification requests failed.".format(failed[hash_bin_type], i, hash_bin_type))
        print("{} of {} {} verification requests failed.".format(failed[hash_b64_type], i, hash_b64_type))
        print(" max. duration: {} sec".format(max_dur))
        max_dur = 0

number_unverified_msgs = len(unverified_json_msgs)
print("{} unverified json msgs".format(number_unverified_msgs))
number_unverified_hashes = len(unverified_hashes)
print("{} unverified hashes".format(number_unverified_hashes))

failed[json_type], failed[hash_bin_type], failed[hash_b64_type] = 0, 0, 0
if number_unverified_msgs > 0:
    print("\nretry verifying {} json messages...".format(number_unverified_msgs))
    for msg in unverified_json_msgs:
        # verify JSON
        r = send_request(url=vrfy_json_url,
                         headers=json_header,
                         data=msg)

        if r.status_code != 200:
            print("NOT VERIFIED: {} ({})".format(msg, json_type))
            print("response: ({}) {}".format(r.status_code, r.text))
            failed[json_type] += 1

    print("{} {}s were unverifiable".format(failed[json_type], json_type))

if number_unverified_hashes > 0:
    print("\nretry verifying {} hashes...".format(number_unverified_hashes))
    for hash in unverified_hashes:
        # verify hash (binary)
        r = send_request(url=vrfy_hash_url,
                         headers=hash_bin_header,
                         data=hash)

        if r.status_code != 200:
            print("NOT VERIFIED: {} ({})".format(binascii.b2a_base64(hash).decode(), hash_bin_type))
            print("response: ({}) {}".format(r.status_code, r.text))
            failed[hash_bin_type] += 1

        # verify hash (base64)
        r = send_request(url=vrfy_hash_url,
                         headers=hash_txt_header,
                         data=binascii.b2a_base64(hash).decode().rstrip('\n'))

        if r.status_code != 200:
            print("NOT VERIFIED: {} ({})".format(binascii.b2a_base64(hash).decode(), hash_b64_type))
            print("response: ({}) {}".format(r.status_code, r.text))
            failed[hash_b64_type] += 1

    print("{} {}es were unverifiable".format(failed[hash_bin_type], hash_bin_type))
    print("{} {}es were unverifiable".format(failed[hash_b64_type], hash_b64_type))
