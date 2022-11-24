import json

import requests


class TestIntegration:
    with open("config.json", "r") as f:
        config = json.load(f)

    host = config["host"]
    auth = config["staticAuth"]
    uuid = config["testDevice"]["uuid"]
    pwd = config["testDevice"]["password"]
    env = config["env"]
    pubkey_url = f"https://identity.{env}.ubirch.com/api/keyService/v1/pubkey/current/hardwareId/{uuid}"

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
        res = requests.get(self.pubkey_url)

        assert len(res.json()) == 1

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
        res = requests.get(self.pubkey_url)

        assert len(res.json()) == 0

    def test_reactivate(self):
        url = self.host + "/device/updateActive"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.auth}
        body = {"id": self.uuid, "active": True}

        res = requests.put(url, json=body, headers=header)

        assert res.status_code == 200
        assert res.content == b'key reactivation successful\n'

        # check if key was registered at ubirch identity service
        res = requests.get(self.pubkey_url)

        assert len(res.json()) == 1
