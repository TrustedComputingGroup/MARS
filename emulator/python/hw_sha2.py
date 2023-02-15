#!/usr/bin/env python3

# Sample Crypt primitives based on SHA256
# Tom Brostrom, CPVI

from hashlib import sha256
import hmac

len_digest = sha256().digest_size # 32
len_sign = len_digest
len_skey = len_digest
len_akey = 0
alg_hash = 0x0b # TPM_ALG_SHA256
alg_sign = 0x5  # TPM_ALG_HMAC
alg_skdf = 0x22 # TPM_ALG_KDF1_SP800_108
alg_akdf = 0

class hashmod:
    digest_size = len_digest
    def new(data=b''):
        return sha256(data)

def CryptHash(data):
    return hashmod.new(data).digest()

# TPM version of 800-108 is in CryptHash.c, CryptKDFa()
# according to part 1 of the TPM Specification.
# Both counter "i" and bit length "L" are encoded in 4 big endian bytes.
# TPM uses 8192 (0x2000) for L.
# Here, i is only 1.

# from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-draft.pdf
def CryptSkdf(key, label, context):
    #  HMAC (key, [i]2 || Label || 0x00 || Context || [L]2) 
    msg = b'\x00\x00\x00\x01' + label + b'\x00' + context + b'\x00\x00\x20\x00'
    return hmac.new(key, msg, sha256).digest()

CryptAkdf = None

def CryptSign(key, dig):
    return hmac.new(key, dig, sha256).digest()

def CryptVerify(key, dig, sig):
    return sig == CryptSign(key, dig)

def CryptSelfTest(fullTest):
    dig = hashmod.new(b'PYTHON').digest()
    exp = bytes.fromhex('329b3dcf798a73e8b87f486bcdaa8e2070f6437f1d470fec6e174ef8ec7b1554')
    return dig == exp

if __name__ == '__main__':
    print('Selftest', CryptSelfTest(True))

    secret = bytes.fromhex('101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f')
    print('sec =', secret.hex())

    ak = CryptSkdf(secret, b'R', b'')
    print(' ak =', ak.hex())

    dig = CryptHash(b'this is a test')
    print('dig =', dig.hex())
    h = hashmod.new()
    h.update(b'this is ')
    h.update(b'a test')
    dig = h.digest()
    print('dig =', dig.hex())

    sig = CryptSign(ak, dig)
    print('sig =', sig.hex())

    print('sig check', CryptVerify(ak, dig, sig))
