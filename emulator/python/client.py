#!/usr/bin/env python3

# MARS Client Attester demo
# T. Brostrom, Cyber Pack Ventures, Inc.

import sys
import socket
import mars
import cbor2 as cbor   # from https://travis-ci.com/agronholm/cbor2, v 5.1.2

from sys import argv
if len(argv) < 2:
    print('Usage:', argv[0], '<hardware module> [<server>]')
    exit()
from importlib import import_module
hwmod = argv[1]
server = argv[2] if len(argv) > 2 else 'localhost'
hw = import_module('hw_' + hwmod)

elog = []
url = 'https://ez_iot.com/endorse'

if (hw.len_skey == 16):
    secret = b'A 16-byte secret'
else:
    secret = b'Here are thirty two secret bytes'

mars = mars.MARS_RoT(hw, secret, 4)
mars.Lock()
mid = mars.Derive(0, b'DeviceIdentifier')[:16]
print('MARS ID', mid.hex())

# Load, Measure, Extend, Execute
# colored modules referenced in PPT animation
dig = hw.CryptHash(b'yellow boot code module')
elog.append((0, dig))
mars.PcrExtend(0, dig)

dig = hw.CryptHash(b'green module')
elog.append((0, dig))
mars.PcrExtend(0, dig)

dig = hw.CryptHash(b'blue module')
elog.append((0, dig))
mars.PcrExtend(0, dig)

dig = hw.CryptHash(b'other stuff')
elog.append((2, dig))
mars.PcrExtend(2, dig)

mars.Unlock()

# open UDP socket to relying party (server)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
srvr = ( server, 21345 )

# send the DEVID
# s.sendto(mid, srvr)
# send the MarsID and BankSize (TODO: no TSR yet)
s.sendto(cbor.dumps((mid, mars.npcr)), srvr)

# read the NONCE
blob, addr = s.recvfrom(1024)
nonce, regsel = cbor.loads(blob)
print('Server:', addr)
print(' Nonce:', nonce.hex())
print('regsel:', hex(regsel))

mars.Lock()
sig = mars.Quote(regsel, nonce, b'')
# must read regs AFTER quote, in case of TSR
pcrs = {i:mars.RegRead(i) for i in range(mars.nreg) if (1<<i)&regsel}
mars.dump()
mars.Unlock()

pem = open('keys/ak.crt', 'rb').read() if hw.CryptAkdf else None

# Generate Canonical Event Log from Native Event Log (elog)
# aggregate events matching PCRs in regsel from elog into CEL
def genCEL(regsel):
    cel = [] # array of CELR (CEL Records)
    for i in range(mars.npcr):
        if (1<<i) & regsel:
            # build CELR for PCR i
            # CELR format:  (recnum, index, digest_list, content)
            diglist = []
            for j,dig in elog:
                # examine elog for events matching i
                if i==j:
                    diglist.append((hw.alg_hash, dig))
            if len(diglist):
                # uses the IMA content (type 7)
                celr = (len(cel), i, diglist, (7, 'MARS', b''))
                cel.append(celr)
    return cel

cel = genCEL(regsel)
blob = cbor.dumps(cel)
# open('cel.bin', 'wb').write(blob)

blob = cbor.dumps( {'HW':hwmod, 'MID':mid, 'Endorser':url,
    'CEL':cel, 'PCRs':pcrs, 'Signature':sig, 'AkCrt':pem, })

# write the blob to blob.bin - can be parsed w/ cbordump (from tinycbor)
# open('blob.bin', 'wb').write(blob)

# send the blob
s.sendto(blob, srvr)

# get the reply
msg = str(s.recv(1024))[2:-1]
# msg = cbor.loads(s.recv(1024))
print('Reply:', msg)

s.close()
