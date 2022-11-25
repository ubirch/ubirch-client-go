import binascii
import json
import random
import uuid

import msgpack
import pytest
import requests

from helpers import get_random_json, serialize, hash_bytes, to_base64


class TestIntegration:
    with open("config.json", "r") as f:
        config = json.load(f)

    host = config["host"]
    auth = config["staticAuth"]
    uuid = config["testDevice"]["uuid"]
    pwd = config["testDevice"]["password"]
    env = config["env"]
    pubkey_url = f"https://identity.{env}.ubirch.com/api/keyService/v1/pubkey/current/hardwareId/{uuid}"
    verify_url = f"https://verify.{env}.ubirch.com/api/upp"

    test_json = {"d": 0, "a": 1, "c": 2, "b": 3}
    test_hash = "6zTRVetfJZONC3QdipR12hIdF7YJL34AWVUSAELrk1Y="

    def test_health(self):
        url = self.host + "/healthz"

        res = requests.get(url)

        assert res.status_code == 200
        assert res.content == b'OK\n'

    def test_ready(self):
        url = self.host + "/readyz"

        res = requests.get(url)

        assert res.status_code == 200
        assert res.content == b'OK\n'

    def test_metrics(self):
        url = self.host + "/metrics"

        res = requests.get(url)

        assert res.status_code == 200
        assert res.content.__contains__(b'# TYPE http_requests_total counter') \
               and res.content.__contains__(b'# TYPE http_response_time_seconds histogram') \
               and res.content.__contains__(b'# TYPE response_status counter')

    def test_register(self):
        url = self.host + "/register"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.auth}
        body = {"uuid": self.uuid, "password": self.pwd}

        res = requests.put(url, json=body, headers=header)

        assert (res.status_code == 200
                and res.content.startswith(b'-----BEGIN CERTIFICATE REQUEST-----\n')
                and res.content.endswith(b'-----END CERTIFICATE REQUEST-----\n')) \
               or (res.status_code == 409
                   and res.content == b'identity already registered\n')

        # check if key was registered at ubirch identity service
        pubkey_res = requests.get(self.pubkey_url)

        assert len(pubkey_res.json()) == 1

    def test_csr(self):
        url = self.host + f"/{self.uuid}/csr"
        header = {'X-Auth-Token': self.auth}

        res = requests.get(url, headers=header)

        assert res.status_code == 200
        assert res.content.startswith(b'-----BEGIN CERTIFICATE REQUEST-----\n') \
               and res.content.endswith(b'-----END CERTIFICATE REQUEST-----\n')

    def test_deactivate(self):
        url = self.host + "/device/updateActive"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.auth}
        body = {"id": self.uuid, "active": False}

        res = requests.put(url, json=body, headers=header)

        assert res.status_code == 200
        assert res.content == b'key deactivation successful\n'

        # check if key was deleted at ubirch identity service
        pubkey_res = requests.get(self.pubkey_url)

        assert len(pubkey_res.json()) == 0

    def test_reactivate(self):
        url = self.host + "/device/updateActive"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.auth}
        body = {"id": self.uuid, "active": True}

        res = requests.put(url, json=body, headers=header)

        assert res.status_code == 200
        assert res.content == b'key reactivation successful\n'

        # check if key was registered at ubirch identity service
        pubkey_res = requests.get(self.pubkey_url)

        assert len(pubkey_res.json()) == 1

    def test_chain(self):
        url = self.host + f"/{self.uuid}"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.pwd}
        data_json = get_random_json()
        data_hash_64 = to_base64(hash_bytes(serialize(data_json)))

        res = requests.post(url, json=data_json, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 6
        assert unpacked[0] == 0x23
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[3] == 0x00
        assert unpacked[4] == binascii.a2b_base64(data_hash_64)

        # check if hash is known by ubirch verification service
        verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})

        assert verify_res.status_code == 200
        assert verify_res.json()["upp"] == res.json()["upp"]

        # todo check if consecutive requests to this endpoint result in correctly chained UPPs

    def test_chain_hash(self):
        url = self.host + f"/{self.uuid}/hash"
        header = {'Content-Type': 'text/plain', 'X-Auth-Token': self.pwd}
        data_hash_64 = to_base64(random.randbytes(32))

        res = requests.post(url, data=data_hash_64, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 6
        assert unpacked[0] == 0x23
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[3] == 0x00
        assert unpacked[4] == binascii.a2b_base64(data_hash_64)

        # check if hash is known by ubirch verification service
        verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})

        assert verify_res.status_code == 200
        assert verify_res.json()["upp"] == res.json()["upp"]

        # todo check if consecutive requests to this endpoint result in correctly chained UPPs

    def test_chain_offline(self):
        url = self.host + f"/{self.uuid}/offline"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.pwd}
        data_json = get_random_json()
        data_hash_64 = to_base64(hash_bytes(serialize(data_json)))

        res = requests.post(url, json=data_json, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        with pytest.raises(KeyError):
            res.json()["response"]

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 6
        assert unpacked[0] == 0x23
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[3] == 0x00
        assert unpacked[4] == binascii.a2b_base64(data_hash_64)

        # make sure hash is unknown by ubirch verification service
        verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})

        assert verify_res.status_code == 404

        # todo check if consecutive requests to this endpoint result in correctly chained UPPs

    def test_chain_offline_hash(self):
        url = self.host + f"/{self.uuid}/offline/hash"
        header = {'Content-Type': 'text/plain', 'X-Auth-Token': self.pwd}
        data_hash_64 = to_base64(random.randbytes(32))

        res = requests.post(url, data=data_hash_64, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        with pytest.raises(KeyError):
            res.json()["response"]

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 6
        assert unpacked[0] == 0x23
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[3] == 0x00
        assert unpacked[4] == binascii.a2b_base64(data_hash_64)

        # make sure hash is unknown by ubirch verification service
        verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})

        assert verify_res.status_code == 404

        # todo check if consecutive requests to this endpoint result in correctly chained UPPs

    def test_anchor(self):
        url = self.host + f"/{self.uuid}/anchor"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.pwd}
        data_json = self.test_json
        data_hash_64 = to_base64(hash_bytes(serialize(data_json)))

        res = requests.post(url, json=data_json, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0x00
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # check if hash is known by ubirch verification service
        verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})

        assert verify_res.status_code == 200
        assert verify_res.json()["upp"] == res.json()["upp"]

    def test_anchor_hash(self):
        url = self.host + f"/{self.uuid}/anchor/hash"
        header = {'Content-Type': 'text/plain', 'X-Auth-Token': self.pwd}
        data_hash_64 = self.test_hash

        res = requests.post(url, data=data_hash_64, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0x00
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # check if hash is known by ubirch verification service
        verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})

        assert verify_res.status_code == 200
        assert verify_res.json()["upp"] == res.json()["upp"]

    def test_disable(self):
        url = self.host + f"/{self.uuid}/disable"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.pwd}
        data_json = self.test_json
        data_hash_64 = to_base64(hash_bytes(serialize(data_json)))

        res = requests.post(url, json=data_json, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0xFA
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # FIXME race-condition or cached hash by verification service makes the following assertion fail sometimes
        # assert hash has been disabled in ubirch backend
        # verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})
        #
        # assert verify_res.status_code == 404

    def test_disable_hash(self):
        url = self.host + f"/{self.uuid}/disable/hash"
        header = {'Content-Type': 'text/plain', 'X-Auth-Token': self.pwd}
        data_hash_64 = self.test_hash

        res = requests.post(url, data=data_hash_64, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0xFA
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # FIXME race-condition or cached hash by verification service makes the following assertion fail sometimes
        # assert hash has been disabled in ubirch backend
        # verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})
        #
        # assert verify_res.status_code == 404

    def test_enable(self):
        url = self.host + f"/{self.uuid}/enable"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.pwd}
        data_json = self.test_json
        data_hash_64 = to_base64(hash_bytes(serialize(data_json)))

        res = requests.post(url, json=data_json, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0xFB
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # FIXME race-condition or cached hash by verification service makes the following assertion fail sometimes
        # assert hash has been enabled in ubirch backend
        # verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})
        #
        # assert verify_res.status_code == 200

    def test_enable_hash(self):
        url = self.host + f"/{self.uuid}/enable/hash"
        header = {'Content-Type': 'text/plain', 'X-Auth-Token': self.pwd}
        data_hash_64 = self.test_hash

        res = requests.post(url, data=data_hash_64, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0xFB
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # FIXME race-condition or cached hash by verification service makes the following assertion fail sometimes
        # assert hash has been enabled in ubirch backend
        # verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})
        #
        # assert verify_res.status_code == 200

    def test_delete(self):
        url = self.host + f"/{self.uuid}/delete"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.pwd}
        data_json = self.test_json
        data_hash_64 = to_base64(hash_bytes(serialize(data_json)))

        res = requests.post(url, json=data_json, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0xFC
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # FIXME race-condition or cached hash by verification service makes the following assertion fail sometimes
        # assert hash has been deleted in ubirch backend
        # verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})
        #
        # assert verify_res.status_code == 404

    def test_delete_hash(self):
        url = self.host + f"/{self.uuid}/delete/hash"
        header = {'Content-Type': 'text/plain', 'X-Auth-Token': self.pwd}
        data_hash_64 = self.test_hash

        res = requests.post(url, data=data_hash_64, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        assert res.json()["response"]["statusCode"] == 200

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0xFC
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # FIXME race-condition or cached hash by verification service makes the following assertion fail sometimes
        # assert hash has been deleted in ubirch backend
        # verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})
        #
        # assert verify_res.status_code == 404

    def test_anchor_offline(self):
        url = self.host + f"/{self.uuid}/anchor/offline"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.pwd}
        data_json = get_random_json()
        data_hash_64 = to_base64(hash_bytes(serialize(data_json)))

        res = requests.post(url, json=data_json, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        with pytest.raises(KeyError):
            res.json()["response"]

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0x00
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # make sure hash is unknown by ubirch verification service
        verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})

        assert verify_res.status_code == 404

    def test_anchor_offline_hash(self):
        url = self.host + f"/{self.uuid}/anchor/offline/hash"
        header = {'Content-Type': 'text/plain', 'X-Auth-Token': self.pwd}
        data_hash_64 = to_base64(random.randbytes(32))

        res = requests.post(url, data=data_hash_64, headers=header)

        assert res.status_code == 200
        assert res.json()["hash"] == data_hash_64
        assert res.json()["publicKey"] == requests.get(self.pubkey_url).json()[0]["pubKeyInfo"]["pubKey"]
        with pytest.raises(KeyError):
            res.json()["response"]

        upp = binascii.a2b_base64(res.json()["upp"])
        unpacked = msgpack.unpackb(upp)
        assert len(unpacked) == 5
        assert unpacked[0] == 0x22
        assert unpacked[1] == uuid.UUID(self.uuid).bytes
        assert unpacked[2] == 0x00
        assert unpacked[3] == binascii.a2b_base64(data_hash_64)

        # make sure hash is unknown by ubirch verification service
        verify_res = requests.post(self.verify_url, data=data_hash_64, headers={'Content-Type': 'text/plain'})

        assert verify_res.status_code == 404

    def test_verify(self):
        # anchor data to verify
        url = self.host + f"/{self.uuid}"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.pwd}
        data_json = get_random_json()
        data_hash_64 = to_base64(hash_bytes(serialize(data_json)))

        signing_res = requests.post(url, json=data_json, headers=header)

        assert signing_res.status_code == 200

        # verify data
        url = self.host + "/verify"
        verify_res = requests.post(url, json=data_json, headers={'Content-Type': 'application/json'})

        assert verify_res.status_code == 200
        assert verify_res.json()["hash"] == data_hash_64
        assert verify_res.json()["upp"] == signing_res.json()["upp"]
        assert verify_res.json()["uuid"] == self.uuid
        assert verify_res.json()["pubKey"] == signing_res.json()["publicKey"]

    def test_verify_hash(self):
        # anchor hash to verify
        url = self.host + f"/{self.uuid}/hash"
        header = {'Content-Type': 'text/plain', 'X-Auth-Token': self.pwd}
        data_hash_64 = to_base64(random.randbytes(32))

        signing_res = requests.post(url, data=data_hash_64, headers=header)

        assert signing_res.status_code == 200

        # verify hash
        url = self.host + "/verify/hash"
        verify_res = requests.post(url, data=data_hash_64, headers={'Content-Type': 'text/plain'})

        assert verify_res.status_code == 200
        assert verify_res.json()["hash"] == data_hash_64
        assert verify_res.json()["upp"] == signing_res.json()["upp"]
        assert verify_res.json()["uuid"] == self.uuid
        assert verify_res.json()["pubKey"] == signing_res.json()["publicKey"]

    def test_verify_offline(self):
        # sign data to verify
        url = self.host + f"/{self.uuid}/offline"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.pwd}
        data_json = get_random_json()
        data_hash_64 = to_base64(hash_bytes(serialize(data_json)))

        signing_res = requests.post(url, json=data_json, headers=header)

        assert signing_res.status_code == 200

        # verify data offline
        url = self.host + "/verify/offline"
        header = {'Content-Type': 'application/json', 'X-Ubirch-UPP': signing_res.json()["upp"]}
        verify_res = requests.post(url, json=data_json, headers=header)

        assert verify_res.status_code == 200
        assert verify_res.json()["hash"] == data_hash_64
        assert verify_res.json()["upp"] == signing_res.json()["upp"]
        assert verify_res.json()["uuid"] == self.uuid
        assert verify_res.json()["pubKey"] == signing_res.json()["publicKey"]

    def test_verify_offline_hash(self):
        # sign hash to verify
        url = self.host + f"/{self.uuid}/offline/hash"
        header = {'Content-Type': 'text/plain', 'X-Auth-Token': self.pwd}
        data_hash_64 = to_base64(random.randbytes(32))

        signing_res = requests.post(url, data=data_hash_64, headers=header)

        assert signing_res.status_code == 200

        # verify hash offline
        url = self.host + "/verify/offline/hash"
        header = {'Content-Type': 'text/plain', 'X-Ubirch-UPP': signing_res.json()["upp"]}
        verify_res = requests.post(url, data=data_hash_64, headers=header)

        assert verify_res.status_code == 200
        assert verify_res.json()["hash"] == data_hash_64
        assert verify_res.json()["upp"] == signing_res.json()["upp"]
        assert verify_res.json()["uuid"] == self.uuid
        assert verify_res.json()["pubKey"] == signing_res.json()["publicKey"]
