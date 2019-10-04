import binascii
import hashlib

import ecdsa

vkb = binascii.a2b_base64("o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZqg==")
sig = binascii.a2b_base64("WQ/xDF7LVU/CVFzqGwopleefBe5xMLFrnkyEUzE08s0pxZgbtudReaWw70FSPvf2f83kgMvd5gfLNBd1V3AGng==")

vk = ecdsa.VerifyingKey.from_string(vkb, curve=ecdsa.curves.NIST256p, hashfunc=hashlib.sha256)
vk.verify(signature=sig,
          data='{"algorithm":"ecdsa-p256v1","created":"2019-10-04T06:35:27.412Z","hwDeviceId":"9a47078c-ff09-478b-a68a-1b3686a2f6f1","pubKey":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZqg==","pubKeyId":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZqg==","validNotAfter":"2020-10-03T06:35:27.412Z","validNotBefore":"2019-10-04T06:35:27.412Z"}'.encode())
