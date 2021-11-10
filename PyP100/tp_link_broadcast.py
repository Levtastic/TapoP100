import random

from zlib import crc32


# (sources) com\tplink\tdp\common\b.java (algorithm)
# (sources) b\d\h\k.java:269 (calling algorithm)
# (sources) com\tplink\tdp\common\c.java (values for calling)
# (sources) b\d\f\e\a.java (int/short to byte conversion)

# Original (relevant) code:

# /* compiled from: TDPPacket */
# public class b {
#     private byte a;

#     /* renamed from: b  reason: collision with root package name */
#     private byte f10641b;

#     /* renamed from: c  reason: collision with root package name */
#     private short f10642c;

#     /* renamed from: d  reason: collision with root package name */
#     private short f10643d;

#     /* renamed from: e  reason: collision with root package name */
#     private byte f10644e;

#     /* renamed from: f  reason: collision with root package name */
#     private byte f10645f;
#     private int g;
#     private int h;
#     protected byte[] i = new byte[0];

#     public b(byte b2, short s, byte b3, String str) {
#         byte[] bArr;
#         this.a = b2;
#         this.f10641b = 0;
#         this.f10642c = s;
#         if (str != null) {
#             bArr = str.getBytes();
#             this.f10643d = (short) bArr.length;
#         } else {
#             this.f10643d = 0;
#             bArr = null;
#         }
#         this.f10644e = b3;
#         this.f10645f = 0;
#         this.g = c();
#         this.h = 1516993677;
#         this.i = new byte[(this.f10643d + 16)];
#         b();
#         if (bArr != null) {
#             System.arraycopy(bArr, 0, this.i, 16, this.f10643d);
#         }
#         a();
#     }

#     private void a() {
#         CRC32 crc32 = new CRC32();
#         crc32.update(this.i);
#         int value = (int) crc32.getValue();
#         this.h = value;
#         System.arraycopy(a.c(value), 0, this.i, 12, 4);
#     }

#     private void b() {
#         byte[] bArr = this.i;
#         byte[] bArr2 = {this.a};
#         System.arraycopy(bArr2, 0, bArr, 0, 1);
#         bArr2[0] = this.f10641b;
#         System.arraycopy(bArr2, 0, bArr, 1, 1);
#         System.arraycopy(a.d(this.f10642c), 0, bArr, 2, 2);
#         byte[] d2 = a.d(this.f10643d);
#         System.arraycopy(d2, 0, bArr, 4, 2);
#         d2[0] = this.f10644e;
#         System.arraycopy(d2, 0, bArr, 6, 1);
#         d2[0] = this.f10645f;
#         System.arraycopy(d2, 0, bArr, 7, 1);
#         System.arraycopy(a.c(this.g), 0, bArr, 8, 4);
#         System.arraycopy(a.c(1516993677), 0, bArr, 12, 4);
#     }

#     private int c() {
#         return new Random().nextInt(268435456) + 0;
#     }
# }


# Decompiled java converted (badly, by hand) to python
class b:
    def __init__(self, b2, s, b3, string):
        bArr = None
        self.a = b2
        self.f10641b = 0
        self.f10642c = s

        if string:
            bArr = string.encode('utf-8')
            self.f10643d = len(bArr)
        else:
            bArr = None
            self.f10643d = 0

        self.f10644e = b3
        self.f10645f = 0

        self.g = self.f_c()

        self.h = 1516993677
        self.i = bytearray(self.f10643d + 16)

        self.f_b()

        if bArr:
            self.arrayCopy(bArr, 0, self.i, 16, self.f10643d)

        self.f_a()

    @staticmethod
    def arrayCopy(src, srcPos, dest, destPos, length):
        dest[destPos:destPos + length] = src[srcPos:srcPos + length]

    def f_a(self):
        value = int(crc32(self.i) & 0xffffffff)
        self.h = value
        self.arrayCopy(self.f_ac(value), 0, self.i, 12, 4)

    def f_b(self):
        bArr = self.i
        bArr2 = [self.a]
        self.arrayCopy(bArr2, 0, bArr, 0, 1)
        bArr2[0] = self.f10641b
        self.arrayCopy(bArr2, 0, bArr, 1, 1)
        self.arrayCopy(self.f_ad(self.f10642c), 0, bArr, 2, 2)
        d2 = self.f_ad(self.f10643d)
        self.arrayCopy(d2, 0, bArr, 4, 2)
        d2[0] = self.f10644e
        self.arrayCopy(d2, 0, bArr, 6, 1)
        d2[0] = self.f10645f
        self.arrayCopy(d2, 0, bArr, 7, 1)
        self.arrayCopy(self.f_ac(self.g), 0, bArr, 8, 4)
        self.arrayCopy(self.f_ac(1516993677), 0, bArr, 12, 4)

    def f_ac(self, value):
        return bytearray(value.to_bytes(4, 'big'))

    def f_ad(self, value):
        return bytearray(value.to_bytes(2, 'big'))

    def f_c(self):
        return random.randrange(268435456)


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

    # class always gets called with these parameters if doing a broadcast
    newb = b(2, 1, 16 | 1, payload)

    for result in broadcast(newb.i):
        print(result)
        print('-' * 10)
