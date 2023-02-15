#!/usr/bin/env python3
# utility function used by MARS and related actors
# Expose crypto primitives as Custody Chain process and verification
# need to use same computations to confirm results.

# convert int i to big endian array of n bytes
def int2bebar(i, n):
    return bytes([i>>(j<<3) & 0xff for j in reversed(range(n))])

def Snapshot(hw, bsize, regsel, PCR, context):
    assert((regsel >> bsize) == 0)  # no stray bits!
    h = hw.hashmod.new()
    h.update(int2bebar(regsel, 4))
    for i in range(bsize):
        if (1<<i) & regsel:
            h.update(PCR[i])
    h.update(context)
    return h

def DeriveAK(hw, DP):
    xkdf = hw.CryptAkdf if hw.CryptAkdf else hw.CryptSkdf
    AK = xkdf(DP, b'R', b'')
    return AK

def DerivePStoDP(hw, PS):
    return hw.CryptSkdf(PS, b'D', b'')

def DpDerive(hw, DP, digest):
    return hw.CryptSkdf(DP, b'D', digest)

def Quote(hw, AK, data):
    return hw.CryptSign(AK, data)
