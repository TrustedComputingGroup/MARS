#!/usr/bin/env python3

# Demo Sealing use case with MARS.
# Sealing data is cryptographically binding data to a device and its state.
# Device is represented by MARS DP.
# State is represented by MARS PCR.
# MARS_Derive() produces the sealing key via the DP and PCR.
# The application performs the en/de-cryption.
# In this demo, the last two #s in a Fibonacci sequence are unsealed,
# the next number is computed, and the last two are sealed.

import hw_ascon as hw
import mars
import os, tempfile
dir = tempfile.gettempdir()
os.chdir(dir)
file = 'fib.bin'

# Get a sealing key (fibkey) from MARS
m = mars.MARS_RoT(hw, b'1234567890123456', 2)
m.Lock()
m.PcrExtend(0, b'$' * 32)
fibkey = m.Derive(0b01, b'fib')
m.Unlock()

# Read and unseal the sealed ciphertext to plaintext
try:
    ct = open(file, 'rb').read()
    pt = hw.ascon_decrypt(fibkey, bytes(16), b'', ct)
except:
    print('New', file, 'in', dir)
    pt = b'FIB 0 1'
if not pt:
    print('Unsealing error')
    exit()

# Get the Fibonacci data
vals = pt.split(b' ', 3)
if len(vals) != 3 or vals[0] != b'FIB':
    print(file, 'format error')
    exit()
f1 = int(vals[1])
f2 = int(vals[2])

# Advanced math to get the next number in sequence
f3 = f1 + f2

# Seal the data and write
pt = 'FIB ' + str(f2) + ' ' + str(f3)
print(pt)
pt = bytearray(pt, encoding='utf-8')
ct = hw.ascon_encrypt(fibkey, bytes(16), b'', pt)
open(file, 'wb').write(ct)

