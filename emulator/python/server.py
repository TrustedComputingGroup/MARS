#!/usr/bin/env python3

# MARS Service Provider (or Relying Party or Verifier) demonstration 
# T. Brostrom, Cyber Pack Ventures, Inc.

# receive connection from client
# challenge client with nonce
# evaluate reply

import os
import subprocess
import time
import socket
import cbor2 as cbor
from mars_util import Snapshot

from importlib import import_module
global hw
hw = None
hwtable = {}
for mod in ( 'she', 'ascon', 'ecc', 'sha2', 'sha3' ):
    hwtable[mod] = import_module('hw_' + mod)

#########################################################
# ENDORSER CODE:
# format is { mid:AK, ... }
# mid = MARS_ID, AK = Attestation Key
dev_db = { 
           bytes.fromhex('502d653484f2759b48343c05f63617cf') : # ASCON
           bytes.fromhex('9f2919b9e58914022b49768c61e27dda'),

           bytes.fromhex('e54e09b0e16c3d9d846d0a135142bbe0') : # SHA2
           bytes.fromhex('fbaf323decb56c8f523e01ab4c2f822b204c91585f980b03c4db3cd5ffa4829c'),

           bytes.fromhex('25ff163da07183077d1a671860cb6d32') : # SHA3
           bytes.fromhex('8169b3420119bc8c185e3e52f0f51f12604b1d0eab77ed8566ed6748bcd56194'),

           bytes.fromhex('4b75937d8e9839e0ae1d4223eb5adba5') : # SHE
           bytes.fromhex('8d307d371edd4e86d2e0f16013babf8a'),
         }

# Check if digest is properly signed by mid's shared AK
def endorse(url, mid, dig, sig):
    print('  ENDORSER', url)
    print('  Query for device', mid.hex())
    try:
        AK = dev_db[mid]
    except:
        print('Unknown device', mid.hex())
        return None
    print('  Found AK', AK.hex())
    print('  Signature check:')
    print('     reported:', sig.hex())
    rc = hw.CryptVerify(AK, dig, sig)
    print('   ', 'Pass' if rc else 'FAIL')
    return rc

# Verify CEL, Canonical Event Log
# CELR format:  (recnum, index, digest_list, content)
def cel_verify(cel, pcrs):
    print('VERIFYING CEL')
    for recnum,index,diglist,content in cel:
        pcr_e = bytes(hw.hashmod.digest_size)
        print('Processing CEL Record', recnum, ', PCR', index)
        for hashalg,dig in diglist:
            assert hashalg == hw.alg_hash
            print('   ', dig.hex())
            # Extend PCR_Expected
            pcr_e = hw.CryptHash(pcr_e + dig)
        print('  expected:', pcr_e.hex())
        if pcr_e != pcrs[index]:
            print('  reported:', pcrs[index].hex())
            return False
    return True

#########################################################
# RELYING PARTY CODE:

trusted_e = [ 'https://ez_iot.com/endorse' ]

# Check that the endorser URL is trusted
def chk_e(url):
    return url in trusted_e

def reply(msg):
    print(str(msg)[2:-1])
    s.sendto(msg, client)

print('RELYING PARTY')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# host = socket.gethostname()
s.bind(('', 21345))

while True:
    # get request from client attester
    blob, client = s.recvfrom(1024)
    mid, bsize = cbor.loads(blob)
    print(' Client:', client)
    print('MARS Id:', mid.hex())
    print('  bsize:', bsize)

    # send challenge to attester
    nonce = os.urandom(16)
    pcrsel = (1<<bsize) - 1 # ask for all PCRs
    print('Sending nonce', nonce.hex(), ' pcrsel', hex(pcrsel))
    s.sendto(cbor.dumps((nonce, pcrsel)), client)

    # receive evidence, aka attestation blob
    blob, client = s.recvfrom(2048)  # should specify client in param

    # Convert attestation blob from CBOR to Python representation
    try:
        att = cbor.loads(blob)
    except Exception:
        reply(b'bad blob received')
        continue

    mod   = att['HW']
    print('   hw:', mod)
    hw = hwtable[mod]
    mid   = att['MID']
    url   = att['Endorser']
    sig_r = att['Signature']
    pcrs  = att['PCRs']
    cel   = att['CEL']
    crt   = att['AkCrt'] if hw.CryptAkdf else None

    print('nonce:', nonce.hex())
    print('  sig:', sig_r.hex())

    # reconstruct snapshot
    dig = Snapshot(hw, bsize, pcrsel, pcrs, nonce).digest()

    # verify the endorser and signature of the snapshot
    if crt:
        print('Asymmetric')
        # Check endorsement of AK
        # Verify that the provided AK-Cert is acceptable
        p = subprocess.run(['openssl', 'verify', '-verbose', '-CAfile', 'keys/ez.crt' ], input=crt)
        if p.returncode:
           reply(b'Invalid AK Certificate')
           continue
        print('AK Cert is good')

        # Verify the signature
        akpub = hw.ECC.import_key(crt)
        r = hw.CryptVerify(akpub, dig, sig_r)
    else:
        print('Symmetric')
        # Check if endorser is trusted
        if not chk_e(url):
            reply(b'Unknown endorser: ' + url )
            continue
        print('Trusted endorser', url)
        # Verify the signature
        r = endorse(url, mid, dig, sig_r)
    if not r:
        reply(b'Invalid signature.')
        continue
    print('Signature is valid. PCR(s) are accurate.')

    # Verify CEL matches signed PCRs
    if not cel_verify(cel, pcrs):
        reply(b'PCR mismatch. CEL is invalid.')
        continue
    print('CEL is accurate.')

    # Could assess PCR and/or CEL digests here

    from datetime import date
    msg = 'Access granted. Date is ' + date.today().strftime('%B %d, %Y.')
    reply(bytes(msg, encoding='UTF-8'))
    # reply(cbor.dumps(msg))
