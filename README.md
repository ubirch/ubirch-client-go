# ubirch-go-udp-client

UDP client example that reads messages from multiple devices
and creates ubirch-protocol secured messages.

This server handles keys and state.

The hashes are generated using SHA256 for the whole UDP payload.

## Install

A `Makefile` is provided to aid compiling and creating an executable for the target architecture.

* build for ARM: run `make`
* copy `start.sh`, `main/ubirch-go-client`, and the `config.json` the target machine
* run `screen ./start.sh` (if it fails, use root or fix screen)
  - to exit screen presse `Ctrl-a d`
  - to reattach to the session, run `screen -R`

The output looks somewhat like this *started and stopped after first packet):
```
2019/10/04 10:29:03 configuration found
2019/10/04 10:29:03 loaded protocol context
2019/10/04 10:29:03 1 certificates, 1 signatures
2019/10/04 10:29:03 UDP server up and listening on :15001
2019/10/04 10:29:05 received 127.0.0.1:35919: 9a47022cff09478ba68a1b3686a2f6f1e30708190d1013b66d0100000000
2019/10/04 10:29:05 CERT [{"pubKeyInfo":{"algorithm":"ecdsa-p256v1","created":"2019-10-04T06:35:27.412Z","hwDeviceId":"9a47022c-ff09-478b-a68a-1b3686a2f6f1","pubKey":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZ44==","pubKeyId":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZ44==","validNotAfter":"2020-10-03T06:35:27.412Z","validNotBefore":"2019-10-04T06:35:27.412Z"},"signature":"WQ/xDF7LVU/CVFzqGwopleefBe5xMLFrnkyEUzE08s0pxZgbtudReaWw70FSPvf2f83kgMvd5gfLNBd1V3AG2g=="}]
2019/10/04 10:29:05 9a47022c-ff09-478b-a68a-1b3686a2f6f1: registered key: (524) {"pubKeyInfo":{"algorithm":"ecdsa-p256v1","created":"2019-10-04T06:35:27.412Z","hwDeviceId":"9a47078c-ff09-478b-a68a-1b3686a2f6f1","pubKey":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZqg==","pubKeyId":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZqg==","validNotAfter":"2020-10-03T06:35:27.412Z","validNotBefore":"2019-10-04T06:35:27.412Z"},"signature":"WQ/xDF7LVU/CVFzqGwopleefBe5xMLFrnkyEUzE08s0pxZgbtudReaWw70FSPvf2f83kgMvd5gfLNBd1V3AGng=="}
2019/10/04 10:29:05 9a47022c-ff09-478b-a68a-1b3686a2f6f1: hash RqIUM3vdS85IVfLYah/x0ebgssk648thMG+IVG0I6FQ= (46a214337bdd4bce4855f2d86a1ff1d1e6e0b2c93ae3cb61306f88546d08e854)
2019/10/04 10:29:05 9a47022c-ff09-478b-a68a-1b3686a2f6f1: UPP 9623c4109a47078cff09478ba68a1b3686a2f6f1c440ce2e42103c7fa58b477ea411c1abdbb90b80505496380f650f94a4c4cd4e0dd198a65e8f5d9fafb37fa16ae0355570e302e331bd74df7085f55c7eafcc4523f800c42046a214337bdd4bce4855f2d86a1ff1d1e6e0b2c93ae3cb61306f88546d08e854c440281dda50dc9b257c3ab4084c02ca28ba5596058fcef8dbe4e7c8f08f7eaafc298ec51cb9c99279af538b337893a3095149cfc47a098c4ca173dd23d96917ec75
2019/10/04 10:29:05 self verification: <nil>: (error: msgpack decode error [pos 0]: cannot decode into value of kind: struct, type: ubirch.chained, ubirch.chained{Version:0x0, Uuid:uuid.UUID{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, PrevSignature:[]uint8(nil), Hint:0x0, Payload:[]uint8(nil), Signature:[]uint8(nil)})
2019/10/04 10:29:06 9a47078c-ff09-478b-a68a-1b3686a2f6f1: "\x96#\xc4\x10\x9d<x\xff\"\xf3DA\xa5х\xc66Ԇ\xff\xc4@\xce.B\x10<\u007f\xa5\x8bG~\xa4\x11\xc1\xab۹\v\x80PT\x968\x0fe\x0f\x94\xa4\xc4\xcdN\rј\xa6^\x8f]\x9f\xaf\xb3\u007f\xa1j\xe05Up\xe3\x02\xe31\xbdt\xdfp\x85\xf5\\~\xaf\xccE#\xf8\x00\x81\xa7message\xbfyour request has been submitted\xc4@\x96\xf0\x88\x8d\x8do;\xaf\xa2\x9b%\xd1{\x9b\t*+H\x86\xbea\x81\vS2S>\a\x14|q\xedUMG\x8f\xd5\xcaRx\xcb{\xf7\xe2\xec\x14\xd2T\x99b\x89A\x92\xc2\xe0\xbd̗\\$J\xf0\a\x04"
2019/10/04 10:29:09 interrupt
2019/10/04 10:29:09 finishing handler
2019/10/04 10:29:09 saved protocol context
```

### Issues

- The configuration from console.demo.ubirch.com sets the msgpack endpoint for 
  key registration. **Remove the `/mpack` from the end of the keyService URL!**

## Copyright

```
Copyright (c) 2019 ubirch GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Authors: Matthias L. Jugel, Waldemar Grünwald, Roxana Meixner