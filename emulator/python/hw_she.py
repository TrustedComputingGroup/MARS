#!/usr/bin/env python3

# Sample Crypt primitives based on AES hash, CMAC and KDF for MARS
# Implements algorithms specified in AUTOSAR Secure Hardware Extensions (SHE)
# Requires pycryptodome
# Author: Tom Brostrom, CPVI

import Crypto.Cipher.AES as aes
import aes_mphash as hashmod

len_digest = hashmod.digest_size
len_sign = 16
len_skey = 16
len_akey = 0
alg_hash = 0x84  # TPM_ALG_? AES_MP
alg_sign = 0x3F # TPM_ALG_CMAC
alg_skdf = 0x86 # unused
alg_akdf = 0    # TPM_ALG_ERROR

# convert int i to big endian array of n bytes
def int2bebar(i, n):
    return bytes([i>>(j<<3) & 0xff for j in reversed(range(n))])

# SHE only supports ECB (default) and CBC modes
# See tests below for examples
def cipher_ecb(key): return aes.new(key, aes.MODE_ECB)
def cipher_cbc(key, iv): return aes.new(key, aes.MODE_CBC, iv=iv)

# Left shift bytearray by 1 bit. Return MSB.
def ls1(a):
    C = 0
    for i in reversed(range(len(a))):
        b = (a[i] << 1) | C
        a[i] = b & 0xff 
        C = b >> 8
    return C

# XOR Byte Arrays # compute x = x ^ y
def xba(x, y):
    assert len(x) == len(y)
    for i in range(len(x)):
        x[i] ^= y[i]

# Simplified CMAC algorithm for a single block.
def cmac1(K, blk):
    assert len(blk) == 16
    E = cipher_ecb(K).encrypt
    mtk = bytearray(E(bytes(16)))       # create the Tweak sub-key k0
    if ls1(mtk): mtk[15] ^= 0x87        # turn k0 into k1
    xba(mtk, blk)                       # create Mn' from k1 ^ blk
    return E(bytes(mtk))                # then encrypt Mn'

# Full CMAC algorithm.
# Unused here.
# Verify with: https://artjomb.github.io/cryptojs-extension/
def cmac(K, msg):
    # print('key =', K.hex())
    E = cipher_ecb(K).encrypt
    mtk = bytearray(E(bytes(16)))       # create the Tweak sub-key k0
    if ls1(mtk): mtk[15] ^= 0x87        # turn k0 into k1

    f = len(msg) >> 4   # full blocks in msg
    r = len(msg) & 0xf  # remainder bytes in last block of msg
    # print('msg =', msg.hex(), " f =", f, ' r =', r)
    if r or not f:                      # partial block, or empty msg
        if ls1(mtk): mtk[15] ^= 0x87    # turn k1 into k2
        last = msg[-r:] + b'\x80' + bytes(15-r)
    else:
        f -= 1
        last = msg[-16:]

    # XOR the tweak sub-key (k1 or k2 in mtk) with last block
    xba(mtk, last)                      # Create Mn': mtk ^= last

    # process all but the last block
    V = bytearray(16)
    for i in range(f):
        xba(V, msg[i<<4:(i+1)<<4])      # V ^= Mi
        V = bytearray(E(bytes(V)))      # V = E(V)

    # process the last tweaked block Mn' in mtk
    xba(V, mtk)                         # V ^= Mn'
    V = E(bytes(V))                     # V = E(V)
    return V

def CryptHash(msg):
    return hashmod.new(msg).digest()

CryptSign = cmac1

def CryptVerify(key, dig, sig):
    return sig == CryptSign(key, dig)

# This KDF is adapted from the AUTOSAR version where
# label and context replace "SHE".
def CryptSkdf(key, label, ctx):
    assert len(label) == 1
    return CryptHash(key + b'\x01\x01' + label + ctx + b'\x00')

CryptAkdf = None

# These tests are from the AUTOSAR SHE spec, 4.13 Examples and Test Vectors
# See https://www.autosar.org/fileadmin/standards/foundation/22-11/AUTOSAR_TR_SecureHardwareExtensions.pdf
def CryptSelfTest(fullTest):

    # ECB TESTS, from spec 4.13.1
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    c = cipher_ecb(key)
    pt  = bytes.fromhex('00112233445566778899aabbccddeeff')
    exp = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    out = c.encrypt(pt)
    assert out == exp
    out = c.decrypt(out)
    assert out == pt

    # CMAC TEST, from spec 4.13.2.3, example 1
    # Same test as RFC 4493, Example 2
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    msg = bytes.fromhex(
        '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51')
    exp = bytes.fromhex('070a16b46b4d4144f79bdd9dd04a287c')
    out = CryptSign(key, msg[:16])
    assert out == exp

    # HASH TEST, from spec 4.13.2.4
    exp = bytes.fromhex('c7277a0dc1fb853b5f4d9cbd26be40c6')
    out = CryptHash(msg)
    assert out == exp

    # HASH UPDATE TEST
    hobj = hashmod.new()
    hobj.update(msg[0:4])
    hobj.update(msg[4:21])
    hobj.update(msg[21:32])
    out = hobj.digest()
    assert out == exp
 
    # KDF TEST, from spec 4.13.2.5
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    exp = bytes.fromhex('118a46447a770d87828a69c222e2d17e')
    out = CryptSkdf(key, b'S', b'HE')
    assert out == exp

    return True


if __name__ == "__main__":

    print('SELF TEST:', 'pass' if CryptSelfTest(True) else 'FAIL')

