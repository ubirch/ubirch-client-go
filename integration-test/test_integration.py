import json

import requests


class TestIntegration:
    with open("config.json", "r") as f:
        config = json.load(f)

    def test_health(self):
        url = self.config["baseURL"] + "/healthz"

        res = requests.get(url)

        assert res.status_code == 200
        assert res.content == b'OK\n'

    def test_ready(self):
        url = self.config["baseURL"] + "/readyz"

        res = requests.get(url)

        assert res.status_code == 200
        assert res.content == b'OK\n'

    def test_metrics(self):
        url = self.config["baseURL"] + "/metrics"

        res = requests.get(url)

        assert res.status_code == 200
        assert res.content.__contains__(b'# TYPE http_requests_total counter') \
               and res.content.__contains__(b'# TYPE http_response_time_seconds histogram') \
               and res.content.__contains__(b'# TYPE response_status counter')

    def test_register(self):
        url = self.config["baseURL"] + "/register"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.config["staticAuth"]}

        res = requests.put(url, json=self.config["testDevice"], headers=header)

        assert (res.status_code == 200
                and res.content.startswith(b'-----BEGIN CERTIFICATE REQUEST-----\n')
                and res.content.endswith(b'-----END CERTIFICATE REQUEST-----\n')) \
               or (res.status_code == 409
                   and res.content == b'identity already registered\n')

        # check if key was registered at ubirch identity service
        uid = self.config["testDevice"]["uuid"]
        env = self.config["env"]
        identity_service_url = f"https://identity.{env}.ubirch.com/api/keyService/v1/pubkey/current/hardwareId/{uid}"

        res = requests.get(identity_service_url)

        assert len(res.json()) == 1

    def test_csr(self):
        uid = self.config["testDevice"]["uuid"]
        url = self.config["baseURL"] + f"/{uid}/csr"
        header = {'X-Auth-Token': self.config["staticAuth"]}

        res = requests.get(url, headers=header)

        assert res.status_code == 200
        assert res.content.startswith(b'-----BEGIN CERTIFICATE REQUEST-----\n') \
               and res.content.endswith(b'-----END CERTIFICATE REQUEST-----\n')

    def test_deactivate(self):
        uid = self.config["testDevice"]["uuid"]
        url = self.config["baseURL"] + "/device/updateActive"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.config["staticAuth"]}
        body = {"id": uid, "active": False}

        res = requests.put(url, json=body, headers=header)

        assert res.status_code == 200
        assert res.content == b'key deactivation successful\n'

        # check if key was deleted at ubirch identity service
        uid = self.config["testDevice"]["uuid"]
        env = self.config["env"]
        identity_service_url = f"https://identity.{env}.ubirch.com/api/keyService/v1/pubkey/current/hardwareId/{uid}"

        res = requests.get(identity_service_url)

        assert len(res.json()) == 0

    def test_reactivate(self):
        uid = self.config["testDevice"]["uuid"]
        url = self.config["baseURL"] + "/device/updateActive"
        header = {'Content-Type': 'application/json', 'X-Auth-Token': self.config["staticAuth"]}
        body = {"id": uid, "active": True}

        res = requests.put(url, json=body, headers=header)

        assert res.status_code == 200
        assert res.content == b'key reactivation successful\n'

        # check if key was registered at ubirch identity service
        uid = self.config["testDevice"]["uuid"]
        env = self.config["env"]
        identity_service_url = f"https://identity.{env}.ubirch.com/api/keyService/v1/pubkey/current/hardwareId/{uid}"

        res = requests.get(identity_service_url)

        assert len(res.json()) == 1
