import binascii
from secrets import token_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import random
from django.db.models import Q
from pyDes import des, CBC, PAD_PKCS5
from random import choice
import string
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import os
from pyDes import *
from . import AES, XOR, rc4, rc4_de
from account import models


def generate_key(password):
    salt = b'\x83\xdb\xb9\xd3\xdc"\x1e\x0ee"\x0c\xf0=5\xab_\x18\xd7\xd2\x98\x92Q.\xbd\x9cK\x96\x93-J\x08\xe0'
    return PBKDF2(password, salt, dkLen=32)


def get_random_key(length, chars=string.ascii_letters + string.digits):
    return ''.join([choice(chars) for i in range(length)])


def decrypt(encrypted_text, key, algorithm_number):
    print('decrypt(encrypted_text, key, algorithm_number):')
    print(key)
    key = key[2:-1]
    key = generate_key(key)
    print('afer decrypt(encrypted_text, key, algorithm_number):')
    print(key)
    print(type(key))
    switch = {1: AES.AES_decrypt, 2: rc4_de.rc4_de, 3: XOR.XOR_decrypt}
    try:
        decrypted_data = switch[algorithm_number](encrypted_text, key)
        print(type(decrypted_data))
        return decrypted_data
    except KeyError as e:
        pass


def decrypt_file(owner, file_name):
    with open(os.path.join("E:\\upload", owner, file_name), 'rb') as input_file:
        encrypted_text = input_file.read()
    file = models.File.objects.get(f_name=file_name[:-4])
    decrypted_text = decrypt(encrypted_text, file.f_key, file.f_switch)  # db find the secret_key, algorithm_number
    # print("type of decry")
    # print(type(decrypt_file()))
    with open(os.path.join("E:\\upload", owner, file_name[:-4]), 'wb') as output_file:
        output_file.write(decrypted_text)
    decryptfile = open(os.path.join("E:\\upload", owner, file_name[:-4]), 'rb')
    decryptfile.seek(0)
    #os.remove(os.path.join("E:\\upload", owner, file_name[:-4]))
    return decryptfile.read()


def encrypt(file_text, file_name, file_owner):
    algorithm_number = random.randint(1, 1)
    switch = {1: AES.AES_encrypt, 2: rc4.rc4, 3: XOR.XOR_encrypt}
    key = get_random_key(8)
    print('en_key')
    print(key)
    print(type(key))
    file_infos = models.File.objects.filter(Q(f_name=file_name) & Q(f_owner=file_owner))
    for file in file_infos:
        file.f_key = key
        file.f_switch = algorithm_number
        file.save()
    key = generate_key(key)  # add salt
    print('encrypt')
    print(key)
    print(type(key))
    try:
        encrypted_data = switch[algorithm_number](file_text, key)
        # encrypted_data = switch[algorithm_number](file_text, key) #save algorithm_number

        return encrypted_data
    except KeyError as e:
        pass


def encrypt_file(file_owner, file_name):
    with open(os.path.join("E:\\upload", file_owner, file_name), 'rb') as input_file:
        plaintext = input_file.read()
        encrypted_text = encrypt(plaintext, file_name, file_owner)
    with open(os.path.join("E:\\upload", file_owner, file_name) + ".enc", 'wb') as output_file:
        output_file.write(encrypted_text)
    os.remove(os.path.join("E:\\upload", file_owner, file_name))


# Now provide AES DES XOR for file encryption, rsa for secret_key encryption
# db saved : file_name algorithm_number key(encrypted)
# API # !!  File_safestorage.encrypt_file(f.name)
#           File_safestorage.decrypt_file(file_info.file_name)
if __name__ == "__main__":
    # AES test: bingo Des:binascii.Error: Non-hexadecimal digit found:decrypted error
    filename = 'test.txt'  # f.name
    secret_key = ''
    encrypt_file(filename)
    print('Your file has already been encrypted')
    option = int(input("Enter 1 to decrypt file."))
    if option == 1:
        decrypt_file(filename + ".enc")
    print('Your file has already been decrypted')

    # XOR test:
    # filename = 'test.txt'  # f.name
    # XORkey = 0
    # encrypt_file(filename)
    # print('Your file has already been encrypted')
    # option = int(input("Enter 1 to decrypt file."))
    # if option == 1:
    #     decrypt_file(filename + ".enc")
    # print('Your file has already been decrypted')
