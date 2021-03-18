import string
from random import choice
from secrets import token_bytes

XORkey = 0


def random_key(length: int) -> int:
    key: bytes = token_bytes(nbytes=length)
    key_int: int = int.from_bytes(key, 'big')
    return key_int


def XOR_encrypt(plain_text, key):
    raw_bytes: bytes = plain_text
    raw_int: int = int.from_bytes(raw_bytes, 'big')
    key_int: int = random_key(len(raw_bytes))
    return raw_int ^ key_int


def XOR_decrypt(encrypted_text, key):
    decrypted: int = encrypted_text ^ key
    length = (decrypted.bit_length() + 7) // 8
    decrypted_bytes: bytes = int.to_bytes(decrypted, length, 'big')
    return decrypted_bytes
