import binascii
import hashlib

import ecdsa

VK = 'H5Ony3urPlsE0RhZi88uAbwDFvouN74SUDO08JaOhLwMqF3vY8gQdUJqd21KFyYj9BRYUIARao0lrbMN4xNbQA=='
binary_vk = binascii.a2b_base64(VK.encode())
vk = ecdsa.VerifyingKey.from_string(binary_vk, curve=ecdsa.curves.NIST256p, hashfunc=hashlib.sha256)
vk.verify(signature=binascii.unhexlify(
    "157becd93e07a6d23a7b063205955716bad992af00a98d5536a16b63caef212637f27b6bae04a64daa91c82254166b6bdadf9908eacc3fe94db0b8d6b3f3478f"),
    data=binascii.unhexlify("46a214337bdd4bce4855f2d86a1ff1d1e6e0b2c93ae3cb61306f88546d08e854"))
