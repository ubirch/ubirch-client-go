import hashlib
import json
import random
import time
import uuid
from binascii import b2a_base64, a2b_base64

import ecdsa

symbols = ("a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F",
           "ä", "ë", "ï", "ö", "ü", "ÿ", "Ä", "Ë", "Ï", "Ö", "Ü", "Ÿ",
           "`", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=",
           "[", "]", ";", "'", "#", ",", ".", "/", "\\",
           "¬", "!", '''"''', "£", "$", "%", "^", "*", "(", ")", "_", "+",
           "{", "}", ":", "@", "~", "?", " |",
           "&", "<", ">", "&#8482",
           "®", "™", "U+2122", "%20", "\\n", "", "\
")


# generates a random JSON message
def get_random_json() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "ts": int(time.time()),
        "big": random.getrandbits(53),
        "tpl": (random.getrandbits(32), "".join(random.choices(symbols, k=4)),
                random.getrandbits(8), "".join(random.choices(symbols, k=8)),
                random.getrandbits(16), "".join(random.choices(symbols, k=2)),
                random.getrandbits(4), "".join(random.choices(symbols, k=16))
                ),
        "lst": random.choices(symbols, k=8),
        "map": {
            random.choice(symbols): random.getrandbits(4),
            random.choice(symbols): random.getrandbits(16),
            random.choice(symbols): random.getrandbits(8),
            random.choice(symbols): random.getrandbits(32)
        },
        "str": "".join(random.choices(symbols, k=128))
    }


def serialize(msg: dict) -> bytes:
    return json.dumps(msg, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()


def get_hash(serialized: bytes) -> bytes:
    return hashlib.sha256(serialized).digest()


def to_base64(hash_bytes: bytes) -> str:
    return b2a_base64(hash_bytes, newline=False).decode()


def verify_upp_signature(upp_bytes: bytes, pubkey_bas64: bytes) -> bool:
    pubkey_bytes = a2b_base64(pubkey_bas64)

    vk = ecdsa.VerifyingKey.from_string(pubkey_bytes, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

    try:
        vk.verify(upp_bytes[-64:], upp_bytes[:-66])
        return True
    except ecdsa.BadSignatureError:
        return False
