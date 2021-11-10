import random

from zlib import crc32


class b:
    def __init__(self, string):
        self.string_length = len(string)

        self.i = bytearray(self.string_length + 16)
        self.i[16:] = string.encode('utf-8')

        self.f_b()

        self.i[12:16] = crc32(self.i).to_bytes(4, 'big')

    def f_b(self):
        self.i[0] = 2
        self.i[1] = 0
        self.i[2:4] = (1).to_bytes(2, 'big')
        self.i[4:6] = self.string_length.to_bytes(2, 'big')
        self.i[6] = 17
        self.i[7] = 0
        self.i[8:12] = random.randrange(268435456).to_bytes(4, 'big')
        self.i[12:16] = (1516993677).to_bytes(4, 'big')


if __name__ == '__main__':
    import socket
    import json

    from select import select
    from Crypto.PublicKey import RSA

    def broadcast(message, *, timeout=0.2, port=20002):
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(0)

        byte_message = bytes(message)
        sock.sendto(byte_message, ("255.255.255.255", port))

        while True:
            data_waiting = select((sock,), (), (), timeout)[0]
            if not data_waiting:
                break

            yield sock.recv(4096)

    # build payload
    key = RSA.generate(2048).publickey().exportKey("PEM")

    payload = json.dumps(
        {'params': {'rsa_key': key.decode("utf-8") + '\n'}},
        separators=(',', ':')
    )

    newb = b(payload)

    for result in broadcast(newb.i):
        print(result)
        print('-' * 10)
