# -*-coding:utf-8-*-
import ast
import base64
import binascii
import hashlib
import random
import socket
import struct
import sys
import threading
import time

from Crypto.Cipher import ARC4

HOST = '127.0.0.1'
PORT = 3368
MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'.encode()
HANDSHAKE_STRING = "HTTP/1.1 101 Switching Protocols\r\n" \
                   "Upgrade: websocket\r\n" \
                   "Connection: Upgrade\r\n" \
                   "Sec-WebSocket-Accept: {1}\r\n" \
                   "WebSocket-Protocol: chat\r\n\r\n"

SESSION_MASTER_KEY = b""


class Th(threading.Thread):
    def __init__(self, connection):
        threading.Thread.__init__(self)
        self.con = connection
        self.p = 0
        self.g = 0
        self.server_rand = ""
        self.server_bob = 0
        self.receive = []
        self.master_key = b''

    def run(self):
        self.receive.append(ast.literal_eval(self.recv_data(1024)))
        if self.receive[-1]["state"] == "hello":
            # receive: client hello
            # send: server hello
            for _ in range(28 * 8):
                self.server_rand += random.choice("01")
            timestamp = str(bin(int(time.time()))).lstrip("0b")
            if len(timestamp) < 32:
                for i in range(32 - len(timestamp)):
                    timestamp = random.choice("01") + timestamp
            elif len(timestamp) > 32:
                timestamp = timestamp[0:32]
            self.server_rand = timestamp + self.server_rand
            tempA = int(self.receive[-1]["exchange"], 2)
            tempB = int(self.server_rand, 2)
            if tempA > tempB:
                self.p = tempA
                self.g = tempB
            else:
                self.p = tempB
                self.g = tempA
            self.send_data(str({
                "state": "hello",
                "exchange": self.server_rand
            }))
        else:
            self.con.close()
        self.receive.append(ast.literal_eval(self.recv_data(1024)))
        if self.receive[-1]["state"] == "key_exchange":
            # receive: client key exchange
            # send: server key exchange
            self.server_bob = random.randint(1, self.p - 2)
            server_key_exchange = self.repeat_mod(self.g, self.server_bob, self.p)
            master_key = self.repeat_mod(int(self.receive[-1]["exchange"], 2), self.server_bob, self.p)
            master_key = bin(master_key).replace("0b", "")
            master_key = (master_key + master_key)[0:256]
            self.master_key = bytes.fromhex(hex(int(master_key, 2)).replace("0x", ""))
            global SESSION_MASTER_KEY
            SESSION_MASTER_KEY = self.master_key
            self.send_data(str({
                "state": "key_exchange",
                "exchange": bin(server_key_exchange).replace('0b', '')
            }))
        else:
            self.con.close()
        self.con.close()
        return self.master_key

    def recv_data(self, num):
        try:
            all_data = self.con.recv(num)
            if not len(all_data):
                return False
        except:
            return False
        else:
            code_len = all_data[1] & 127
            if code_len == 126:
                masks = all_data[4:8]
                data = all_data[8:]
            elif code_len == 127:
                masks = all_data[10:14]
                data = all_data[14:]
            else:
                masks = all_data[2:6]
                data = all_data[6:]
            raw_str = ""
            i = 0
            for d in data:
                raw_str += chr(d ^ masks[i % 4])
                i += 1
            return raw_str

    def repeat_mod(self, e, n, m):
        n = bin(int(n))
        n = n.replace('0b', '')
        n = n[::-1]
        a = [1]
        b = [int(e)]
        m = int(m)
        cum = 0
        for i in n:
            if int(i) > 0:
                a.append(a[cum] * b[cum] % m)
            else:
                a.append(a[cum] % m)
            if cum < len(n):
                b.append(b[cum] * b[cum] % m)
                cum = cum + 1
        return a[cum]

    # send data
    def send_data(self, data):
        if data:
            data = str(data)
        else:
            return False
        token = b"\x81"
        length = len(data)
        if length < 126:
            token += struct.pack("B", length)
        elif length <= 0xFFFF:
            token += struct.pack("!BH", 126, length)
        else:
            token += struct.pack("!BQ", 127, length)
        data = token + data.encode()
        self.con.send(data)
        return True


def rc4_encrypt(data, key):
    rc41 = ARC4.new(key)
    return rc41.encrypt(data)


def rc4_decrypt(data, key):
    rc41 = ARC4.new(key)
    return rc41.decrypt(data)


def decrypt(recv: str):
    r_mac = recv[-64:]
    r_data = recv[0:len(recv) - 64]
    x = hashlib.sha256()
    x.update(r_data.encode())
    print(x.hexdigest())
    print(r_mac)
    if x.hexdigest() == r_mac:
        print("haha")
        decrypted_data = rc4_decrypt(bytes.fromhex(r_data), SESSION_MASTER_KEY)
        file_data = bytes.fromhex(decrypted_data.decode())
        return file_data


def encrypt(send: str):
    send = binascii.b2a_hex(send).decode("utf-8")
    data = rc4_encrypt(send.encode(), SESSION_MASTER_KEY)
    data = binascii.b2a_hex(data).decode("utf-8")
    x = hashlib.sha256()
    x.update(data.encode())
    return data + x.hexdigest()


def write_file(bytestring: bytes):
    with open("aaa.docx", "wb+") as f:
        f.write(bytestring)


def handshake(con):
    headers = {}
    shake = con.recv(1024).decode()
    print(shake)
    if not len(shake):
        return False
    header, data = shake.split('\r\n\r\n', 1)
    for line in header.split('\r\n')[1:]:
        key, val = line.split(': ', 1)
        headers[key] = val

    if 'Sec-WebSocket-Key' not in headers:
        print('This socket is not websocket, client close.')
        con.close()
        return False

    sec_key = headers['Sec-WebSocket-Key'].encode()
    res_key = base64.b64encode(hashlib.sha1(sec_key + MAGIC_STRING).digest()).decode()

    str_handshake = HANDSHAKE_STRING.replace('{1}', res_key).replace('{2}', HOST + ':' + str(PORT)).encode()
    con.send(str_handshake)
    return True


def service():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', 2345))
        sock.listen(5)
        print("bind 3368,ready to use")
    except:
        print("Server is already running,quit")
        sys.exit()

    connection, address = sock.accept()
    print("Got connection from ", address)
    if handshake(connection):
        print("handshake success")
        try:
            t = Th(connection)
            t.start()
            t.join()
            print('new thread for client ...')
        except:
            print('start new thread error')
            connection.close()


if __name__ == '__main__':
    service()
