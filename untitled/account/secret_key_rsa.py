import base64
import rsa

hash = "SHA-256"
PUBLIC_KEY_PATH = 'D:\\Users/company_rsa_public_key.pem'
PRIVATE_KEY_PATH = 'D:\\Users/company_rsa_private_key.pem'
company_public_key = b''
company_private_key = b''


def get_keys(company_pub_file=PUBLIC_KEY_PATH, company_pri_file=PRIVATE_KEY_PATH):
    global company_public_key, company_private_key
    if company_pub_file:
        pub = open(company_pub_file).read()
        pub = bytes(pub, encoding='utf8')
        company_public_key = rsa.PublicKey.load_pkcs1_openssl_pem(pub)

    if company_pri_file:
        pri = open(company_pri_file).read()
        pri = bytes(pri, encoding='utf8')
        company_private_key = rsa.PrivateKey.load_pkcs1(pri, 'PEM')  # must be PKS1!!!

    return company_public_key, company_private_key


def encrypt_by_public_key(plaintext):
    plaintext = bytes(plaintext, encoding='utf8')
    public_key, private_key = get_keys()
    input_text = plaintext
    out_text = rsa.encrypt(input_text, public_key)
    encrypt_result = out_text
    encrypt_result = base64.b64encode(encrypt_result)
    return encrypt_result


def decrypt_by_private_key(en_txt):
    en_txt = en_txt[2:-1]
    print(en_txt)
    public_key, private_key = get_keys()
    decrypt_message = base64.b64decode(en_txt)
    input_text = decrypt_message
    out = rsa.decrypt(input_text, private_key)
    decrypt_result = out
    return decrypt_result


if __name__ == "__main__":
    encrypt_message = 'CZT0naD7xeVR32WHgfQFWkbTpqRWaR29hkyfZ9H1oH3yGyoxPlFY/0+QXBggI3+3s8vTmC7ALpS/xAGjRetOVUnRtfsp2/+V1xUTZb1bSHxqPNJeNYBoYyu/a77owK4S6G4oEstjF9cyucoEaXXJBkZLlQIowydzrjFRUnUP66Y='
    print(type(encrypt_message))
    print(encrypt_message)
    pub_key, pri_key = get_keys()
    # print(pub_key)
    # print(pri_key)
    # message = bytes(message, encoding="utf8")
    # encrypt_message = encrypt_by_public_key(message)
    # print('encrypt_message')
    # print(encrypt_message)
    message = decrypt_by_private_key(encrypt_message)
    print('decrypt_message')
    print(message)
