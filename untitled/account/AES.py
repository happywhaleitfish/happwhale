from Crypto.Cipher import AES
from Crypto import Random


def AES_encrypt(plain_text, key, key_size=256):
    print('AES encrypt')
    pad = lambda s: s + b"\0" * (AES.block_size - len(s) % AES.block_size)
    text = pad(plain_text)
    initialization = Random.new().read(16)
    cipher = AES.new(key, AES.MODE_CBC, initialization)
    return initialization + cipher.encrypt(text)


def AES_decrypt(encrypted_text, key):
    print('AES decrypt')
    print(key)
    initialization = encrypted_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, initialization)
    plaintext = cipher.decrypt(encrypted_text[AES.block_size:])

    return plaintext.rstrip(b"\0")
