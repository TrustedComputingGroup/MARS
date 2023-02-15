#!/usr/bin/env python3

"""
Sample Crypt primitives based on Ascon for MARS
T. Brostrom
"""

from ascon.ascon import ascon_hash, ascon_encrypt, ascon_decrypt
CryptHash = ascon_hash

len_digest = 32
len_sign = 16
len_skey = 16
len_akey = 0
alg_hash = 0x81 # TPM_ALG_? ASCON_HASH
alg_sign = 0x82 # unused
alg_skdf = 0x83 # unused
alg_akdf = 0    # TPM_ALG_ERROR

# Simple hasher if update is not natively supported
class hash:
    digest_size = len(CryptHash(b''))
    def __init__(self, msg=b''):
        # self.digest_size = CryptHasher.digest_size
        self.partial = msg

    def update(self, msg):
        self.partial += msg

    def digest(self):
        return CryptHash(self.partial)

class hashmod:
    digest_size = hash().digest_size
    def new(data=b''):
        return hash(data)

# There is no standard KDF using Ascon
# so, fake it
# Create a tag using label as nonce
def CryptSkdf(k, label, context):
    label += bytes(16-len(label))
    return ascon_encrypt(k, label, context, b'')

CryptAkdf = None

def CryptSign(key, dig):
    # ascon_encrypt(key, nonce, associateddata, plaintext)
    label = b'Z'
    label += bytes(16-len(label))
    print("SIGN: key", key.hex())
    print("SIGN: nnc", label.hex())
    print("SIGN:  ad", dig.hex())
    sig = ascon_encrypt(key, label, dig, b'')
    print("SIGN: sig", sig.hex())
    return sig

def CryptVerify(key, dig, sig):
    # ascon_decrypt(key, nonce, associateddata, ciphertext)
    label = b'Z'
    label += bytes(16-len(label))
    return ascon_decrypt(key, label, dig, sig) != None

def CryptSelfTest(fullTest):
    # Tests from within original ascon.py
    # demo_hash("Ascon-Hash")
    ad = b'ASCON'
    pt = b'ascon'
    exp = bytes.fromhex('02c895cb92d79f195ed9e3e2af89ae307059104aaa819b9a987a76cf7cf51e6e')
    out = CryptHash(pt)
    assert out == exp

    # demo_aead('Ascon-128')
    key = bytes.fromhex('8863ccbca647c1dc590f5e5de94bfa96')
    nonce = bytes.fromhex('b84c82903adad9f2a987e837286cb994')
    exp = bytes.fromhex('0a150c9ac3 c7e08e4c94ae8c1296148806aa68b67e')
    ct = ascon_encrypt(key, nonce, ad, pt, 'Ascon-128')
    assert ct == exp

    pt2 = ascon_decrypt(key, nonce, ad, ct)
    assert pt2 == pt

    return True


if __name__ == "__main__":

    print('SELF TEST:', 'pass' if CryptSelfTest(True) else 'FAIL')
