import binascii
import hashlib
import sys

import requests

if len(sys.argv) < 3:
    print("usage:")
    print("python3 ./api_test.py <UUID> <AUTH_TOKEN>")
    sys.exit()

uuid = sys.argv[1]
auth = sys.argv[2]

url_base = 'http://localhost:8080'
url_sign = url_base + '/{}'.format(uuid)
url_sign_hash = url_base + '/{}/hash'.format(uuid)
url_vrfy = url_base + '/verify'.format(uuid)
url_vrfy_hash = url_base + '/verify/hash'.format(uuid)

header_auth = {'X-Auth-Token': auth}
header_bin = {'Content-Type': 'application/octet-stream'}
header_json = {'Content-Type': 'application/json'}

msg_json = '{"data":{"H":"55","T":"25.5"}}'.encode()
msg_bin = "test binary".encode()
msg_hash = binascii.a2b_base64("dl/c6FzLMDdqtG/nKKxAlbx0mP+8IlLuiU9IhzF1838=")

# sign json
print("sign json: {}".format(msg_json.decode()))
r = requests.post(url=url_sign,
                  headers={**header_auth, **header_json},
                  data=msg_json)
print("response: ({}) {}\n".format(r.status_code, r.text))

# verify json
print("verify json: {}".format(msg_json.decode()))
r = requests.post(url=url_vrfy,
                  headers=header_json,
                  data=msg_json)
print("response: ({}) {}\n".format(r.status_code, r.text))

# sign binary
print("sign binary: {}".format(msg_bin))
print("hash: {}".format(binascii.b2a_base64(hashlib.sha256(msg_bin).digest()).decode().rstrip('\n')))
r = requests.post(url=url_sign,
                  headers={**header_auth, **header_bin},
                  data=msg_bin)
print("response: ({}) {}\n".format(r.status_code, r.text))

# verify binary
print("verify binary: {}".format(msg_bin))
r = requests.post(url=url_vrfy,
                  headers=header_bin,
                  data=msg_bin)
print("response: ({}) {}\n".format(r.status_code, r.text))

# sign hash
print("sign hash: {}".format(binascii.b2a_base64(msg_hash).decode().rstrip('\n')))
r = requests.post(url=url_sign_hash,
                  headers={**header_auth, **header_bin},
                  data=msg_hash)
print("response: ({}) {}\n".format(r.status_code, r.text))

# verify hash
print("verify hash: {}".format(binascii.b2a_base64(msg_hash).decode().rstrip('\n')))
r = requests.post(url=url_vrfy_hash,
                  headers=header_bin,
                  data=msg_hash)
print("response: ({}) {}\n".format(r.status_code, r.text))
