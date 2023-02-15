#!/usr/bin/env python3

# Sample Crypt primitives based on SHA256 and ECC/DSS for MARS
# based loosly on subset of MARS Spec draft 0.31
# Requires pycryptodome
# Tom Brostrom, CPVI

from Crypto.Hash import SHA256 as hashmod
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import random

len_digest = hashmod.digest_size # 32
len_sign = 64
len_skey = 16
len_akey = 0    # TODO
alg_hash = 0xB  # TPM_ALG_SHA256
alg_sign = 0x18 # TPM_ALG_ECDSA
alg_skdf = 0x87 # unused
alg_akdf = 0x23 # TPM_ALG_ECC ?

drbg_init = random.seed

def drbg(n):
    i = random.getrandbits(8*n)
    # convert int i to little endian array of n bytes
    b = bytes([i>>(j<<3) & 0xff for j in range(n)])
    # print(n, b.hex())
    return b

def CryptHash(data):
    return hashmod.new(data).digest()

# TODO: horribly wrong ?
def CryptSkdf(key, x, y):
    assert len(key) == len_skey
    drbg_init(key + x + y)
    return drbg(len_skey)

def CryptAkdf(key, x, y):
    print('Akdf key', key.hex(), 'x', x.hex(), 'y', y.hex())
    drbg_init(key + x + y)
    new = ECC.generate(curve='P-256', randfunc=drbg)
    print('Akdf:', hex(new.d)[2:])
    return new

# Hasher_dummy is a hack to make an externally produced digest,
# look like it was produced locally, and part of a hasher object.
# This is needed by pycryptodome's DSS.
# DSS needs digest() and digest_size.
# HMAC needs block_size and new().

class Hasher_dummy:  # to make DSS sign() and verify() happy
    block_size = 0
    def __init__(self, data):
        self.dig = data
        self.digest_size = hashmod.digest_size # len(data)
        self.block_size = self.digest_size # ?
    def digest(self):
        return self.dig
    def new(self, stuff):
        return hashmod.new(stuff)

def CryptSign(key, dig):
    hd = Hasher_dummy(dig)
    return DSS.new(key, 'deterministic-rfc6979').sign(hd)
    # or 'fips-186-3'

def CryptVerify(pub, dig, sig):
    # verify = DSS.new(pub, 'fips-186-3').verify
    verify = DSS.new(pub, 'deterministic-rfc6979').verify
    rc = True
    try:
        verify(Hasher_dummy(dig), sig)
    except ValueError:
        rc = False
    # print('Good' if rc else 'bad')
    return rc

def CryptSelfTest(fullTest):
    dig = hashmod.new(b'PYTHON').digest()
    exp = bytes.fromhex('329b3dcf798a73e8b87f486bcdaa8e2070f6437f1d470fec6e174ef8ec7b1554')
    return dig == exp


if __name__ == '__main__':
    from os import urandom

    print('SelfTest:', CryptSelfTest(True))

    secret = bytes.fromhex('101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f')

    dig = CryptHash(b'this is a test')
    print('dig =', dig.hex())
    h = hashmod.new()
    h.update(b'this is ')
    h.update(b'a test')
    dig = h.digest()
    print('dig =', dig.hex())

    prv = CryptAkdf(secret, b'R', b'')
    pub = prv.public_key()

    sig = CryptSign(prv, dig)
    print('sig =', sig.hex())

    print('Verify', CryptVerify(pub, dig, sig))
