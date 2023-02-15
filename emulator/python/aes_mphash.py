#!/usr/bin/env python3

# Sample Crypt primitives based on AES hash, CMAC and KDF for MARS
# Implements algorithms specified in AUTOSAR Secure Hardware Extensions (SHE)
# Requires pycryptodome
# Author: Tom Brostrom, CPVI

import Crypto.Cipher.AES as aes

# convert int i to big endian array of n bytes
def int2bebar(i, n):
    return bytes([i>>(j<<3) & 0xff for j in reversed(range(n))])

# Miyaguchi–Preneel (MP) compression
# https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi–Preneel
# apply MP round to each block in msg
def mp_comp(msg, H = bytes(16)):
    for i in range( len(msg) >> 4 ):
        M = msg[i<<4:(i+1)<<4]
        EkM = aes.new(H, aes.MODE_ECB).encrypt(M)
        H = bytes([H[j] ^ EkM[j] ^ M[j] for j in range(16)])
    return H

# Pad message with a 1 bit (in 0x80), 0 bytes, and
# 5 bytes containing the message's bit length
def pad(msg, total=None):
    if total is None: total = len(msg)
    r = len(msg) & 0xf                  # remainder bytes in last block of msg
    z = (10 if r<=10 else 26) - r       # z = number of 0 bytes pad
    return msg + b'\x80' + bytes(z) + int2bebar(total*8, 5)

class hash:
    digest_size = 16
    def __init__(self, data=b''):
        self.digest_size = hash.digest_size
        self.H = bytes(self.digest_size)
        self.partial = b''
        self.total = 0
        self.update(data)

    def update(self, msg):
        self.total += len(msg)
        msg = self.partial + msg
        self.H = mp_comp(msg, self.H)
        r = len(msg) & 0xf                 # bytes in last partial block
        self.partial = msg[-r:] if r else b''

    def digest(self):
        #p = pad(self.partial, self.total)
        #print("fini pad", p.hex())
        #return mp_comp( p, self.H )
        return mp_comp( pad(self.partial, self.total), self.H )

digest_size = hash.digest_size
def new(data=b''):
    return hash(data)

# def CryptHash(msg):
    # return mp_comp(pad(msg))
    # return new(msg).digest()

if __name__ == "__main__":

    # HASH TESTS

    msg = bytes.fromhex(
        '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51')
    exp = bytes.fromhex('c7277a0dc1fb853b5f4d9cbd26be40c6')
    out = new(msg).digest()
    print('HASH TEST:', 'pass' if out == exp else 'FAIL')

    hobj = new()
    hobj.update(msg[0:4])
    hobj.update(msg[4:21])
    hobj.update(msg[21:32])
    out = hobj.digest()
    print('SEQ TEST:', 'pass' if out == exp else 'FAIL')
