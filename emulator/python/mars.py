#!/usr/bin/env python3

# Sample MARS based loosly on the MARS Library and API specs.
# It supports SequenceEvent() which was dropped from the spec.
# Author: Tom Brostrom, CPVI

from threading import Lock, current_thread
from enum import Enum
import time # for TSR

# convert int i to big endian array of n bytes
def int2bebar(i, n):
    return bytes([i>>(j<<3) & 0xff for j in reversed(range(n))])

class MARS_RoT:
    """A MARS Root of Trust is instantiated with a hardware (hw) module
    that provides cryptographic services, a secret seed, the number of PCR,
    and optionally a debug flag.
    """

    class PT(Enum):
        PCR = 1
        TSR = 2
        LEN_DIGEST = 3
        LEN_SIGN = 4
        LEN_KSYM = 5
        LEN_KPUB = 6
        LEN_KPRV = 7
        ALG_HASH = 8
        ALG_SIGN = 9
        ALG_SKDF = 10
        ALG_AKDF = 11

    def __init__(self, hw, secret, npcr, debug=False):
        self.debug = debug
        self.npcr = npcr
        self.ntsr = 1
        self.nreg = self.npcr + self.ntsr
        if debug: print('Provisioning of new MARS device')
        assert len(secret) == hw.len_skey
        assert self.nreg > 0 and self.nreg <= 32
        self.hw = hw                    # hardware, i.e. Crypt methods
        self.CryptXkdf = hw.CryptAkdf if hw.CryptAkdf else hw.CryptSkdf
        self.PS = secret                # Primary Seed
        self.hobj = None
        self.seqpcr = None
        self.lock = Lock()
        self.thread = None

        # init PCR and TSR
        self.REG = [bytes(self.hw.len_digest) for _ in range(self.nreg)]
        self.failure = False
        self.Lock()
        self.SelfTest(True)
        self.CryptDpInit()
        self.Unlock()
        

    # MANAGEMENT API

    def locked(self):
        """Internal method to determine if MARS is locked by the caller.
        """
        return self.lock.locked() and self.thread == current_thread()

    def SelfTest(self, fullTest):
        """Initiate the HW's self-testing mechanism."""
        assert self.locked()
        if not self.failure:
            self.failure = not self.hw.CryptSelfTest(fullTest)
        return not self.failure

    def Lock(self):
        """Attempt to lock this MARS instance for exclusive use."""
        assert not self.locked()
        self.lock.acquire()
        assert not self.thread
        self.thread = current_thread()

    def Unlock(self):
        """Release the exclusive-use lock."""
        assert self.locked()
        self.hobj = None
        # other cleanup?
        self.thread = None
        self.lock.release()

    def CapabilityGet(self, pt):
        """Returns a MARS capability value indicated by the property tag pt."""
        if pt == self.PT.PCR: return self.npcr
        if pt == self.PT.TSR: return self.ntsr
        if pt == self.PT.LEN_DIGEST: return self.hw.len_digest
        if pt == self.PT.LEN_SIGN: return self.hw.len_sign
        if pt == self.PT.LEN_KSYM: return self.hw.len_skey
        if pt == self.PT.LEN_KPUB: return self.hw.len_akey
        # if pt == self.PT.LEN_KPRV: return self.hw.len_
        if pt == self.PT.ALG_HASH: return self.hw.alg_hash
        if pt == self.PT.ALG_SIGN: return self.hw.alg_sign
        if pt == self.PT.ALG_SKDF: return self.hw.alg_skdf
        if pt == self.PT.ALG_AKDF: return self.hw.alg_akdf
        return None

    # SUPPORT FUNCTIONS

    def dump(self):
        """Display state of MARS. Not part of standard API."""
        assert self.locked()
        if self.debug:
            print('--------------------------')
            print('MARS PRIVATE CONFIGURATION')
            print('     PS:', self.PS.hex())
            print('     DP:', self.DP.hex())
            for i in range(self.nreg):
                print(' REG[' + str(i) + ']: ' + self.REG[i].hex())
            print('--------------------------')

    def CryptDpInit(self):
        """Set the value of the Derivation Parent (DP) using the PS.
        This should be using a profile-specific algorithm.
        For now, a simple Skdf is used."""
        self.DP = self.hw.CryptSkdf(self.PS, b'D', b'dbg' if self.debug else b'prd')

    def CryptSnapshot(self, regsel, ctx):
        """Create a "snapshot" - picture/digest of the MARS state and the provided context."""
        assert (regsel >> self.nreg) == 0   # no stray bits!

        # Example of supplemental code to sample a TSR
        def sample(tsr):
            if self.debug: print('Sampling TSR', tsr)
            return int2bebar(time.monotonic_ns(), self.hw.len_digest)

        # TSRs, if any, are written at this point
        for tsr in range(self.ntsr):
            i = self.npcr + tsr
            if (1<<i) & regsel:
                self.REG[i] = sample(tsr)

        h = self.hw.hashmod.new()
        h.update(int2bebar(regsel, 4))
        for i in range(self.nreg):
            if (1<<i) & regsel:
                h.update(self.REG[i])
        h.update(ctx)
        return h.digest()

    # SEQUENCED PRIMITIVES

    def SequenceHash(self):
        """Start a hashing sequence."""
        assert self.locked()
        assert not self.hobj
        self.hobj = self.hw.hashmod.new()

    def SequenceEvent(self, ipcr):
        """SequenceEvent support was dropped from the spec since this was
        seen as a simple convenience function, and not a primitive."""
        assert self.locked()
        assert ipcr >= 0 and ipcr < self.npcr
        assert self.seqpcr is None
        self.seqpcr = ipcr
        self.SequenceHash()

    def SequenceUpdate(self, data):
        """Process the provided data under the current sequence algorithm."""
        assert self.locked()
        assert self.hobj
        self.hobj.update(data)

    def SequenceComplete(self):
        """Indicates the end of a sequenced parameter. Data processed in the sequence is returned."""
        assert self.locked()
        assert self.hobj
        dig = self.hobj.digest()
        self.hobj = None
        if self.seqpcr is not None:
            self.PcrExtend(self.seqpcr, dig)
            self.seqpcr = None
        return dig

    # INTEGRITY COLLECTION

    def PcrExtend(self, i, dig):
        """Updates PCR[i] = HASH( PCR[i] || dig )"""
        assert self.locked()
        assert i >= 0 and i < self.npcr
        assert len(dig) == self.hw.len_digest
        self.REG[i] = self.hw.CryptHash(self.REG[i] + dig)

    def RegRead(self, i):
        """Returns the contents of the indicated register (PCR or TSR)."""
        assert self.locked()
        assert i >= 0 and i < self.nreg
        return self.REG[i]

    # KEY MANAGEMENT

    def Derive(self, regsel, ctx):
        """Generates bytes for external use by using CryptSkdf() with the DP, a device snapshot, and a label of 'X'."""
        assert self.locked()
        snapshot = self.CryptSnapshot( regsel, ctx )
        return self.hw.CryptSkdf(self.DP, b'X', snapshot)

    def DpDerive(self, regsel, ctx):
        """Compute a new value of DP via KDF of the current DP, register selection, selected register
        values and provided context, ctx. If ctx is NULL, the DP is reset to its initial state."""
        assert self.locked()
        if ctx == None:
            self.CryptDpInit()
            # self.DP = self.hw.CryptSkdf(self.PS, b'D', b'')
        else:
            snapshot = self.CryptSnapshot( regsel, ctx )
            self.DP = self.hw.CryptSkdf(self.DP, b'D', snapshot)

    def PublicRead(self, restricted, ctx):
        """Returns the public portion of the specified asymmetric key."""
        assert self.locked()
        assert self.hw.CryptAkdf
        label = b'R' if restricted else b'U'
        key = self.hw.CryptAkdf(self.DP, label, ctx)
        return key.public_key()

    # ATTESTATION

    def Quote(self, regsel, nonce, ctx):
        """Returns a signature of a snapshot of the current device state as reflected
        in the selected registers with the designated restricted key."""
        assert self.locked()
        snapshot = self.CryptSnapshot( regsel, nonce )
        AK = self.CryptXkdf(self.DP, b'R', ctx)
        if self.debug:
            if (self.hw.CryptAkdf):
                print('AK =', AK.public_key().export_key(format='PEM'))
                #print('AKpub', pem)
            else:
                print('AK =', AK.hex())
        return self.hw.CryptSign(AK, snapshot)

    def Sign(self, ctx, dig):
        """Returns a signature of an externally provided digest with the designated unrestricted key."""
        assert self.locked()
        assert ctx # must not be Null
        key = self.CryptXkdf(self.DP, b'U', ctx)
        return self.hw.CryptSign(key, dig)

    def SignatureVerify(self, restricted, ctx, dig, sig):
        """Returns a verdict of digital signature verification using CryptVerify()"""
        assert self.locked()
        label = b'R' if restricted else b'U'
        key = self.CryptXkdf(self.DP, label, ctx)
        return self.hw.CryptVerify(key, dig, sig)

if __name__ == '__main__':

    from os import urandom
    from sys import argv
    if len(argv) != 2:
        print('Usage:', argv[0], '<hardware module>')
        exit()
    from importlib import import_module
    hw = import_module('hw_' + argv[1])

    if (hw.len_skey == 16):
        secret = b'A 16-byte secret'
    else:
        secret = b'Here are thirty two secret bytes'

    mars = MARS_RoT(hw, secret, 4, True)

    dig = hw.CryptHash(b'this is a test')
    print('dig =', dig.hex())
    mars.Lock()
    mars.SequenceHash()
    mars.SequenceUpdate(b'this is ')
    mars.SequenceUpdate(b'a test')
    dig = mars.SequenceComplete()
    mars.Unlock()
    print('dig =', dig.hex())

    mars.Lock()
    mars.PcrExtend(0, dig)
    dig = mars.RegRead(0)
    print('REG 0 ', dig.hex())

    mars.SequenceEvent(1)
    mars.SequenceUpdate(b'this is a ')
    mars.SequenceUpdate(b'test')
    mars.SequenceComplete()
    assert dig == mars.RegRead(1)

    cdi = mars.Derive(1, b'CompoundDeviceID')
    mars.Unlock()
    print('CDI', cdi.hex())

    # nonce = urandom(16)
    nonce = b'Q' * mars.hw.len_digest

    mars.Lock()
    sig = mars.Quote(1<<0, nonce, b'')
    mars.Unlock()
    print('SIG ', sig.hex())

    mars.Lock()
    mars.dump()
    mars.DpDerive(0, b'XYZZY')
    mars.dump()
    sig = mars.Quote(1<<0, nonce, b'')
    print('SIG ', sig.hex())

    # dig = mars.CryptSnapshot(1<<0, nonce)
    dig = hw.CryptHash(b'\x00\x00\x00\x01' + mars.RegRead(0) + nonce)
    print('dig ', dig.hex())
    print('Verified? ', 'Success' if mars.SignatureVerify(True, b'', dig, sig) else 'FAIL')

    cdi = mars.Derive(1, b'CompoundDeviceID')
    print('CDI2', cdi.hex())
    mars.DpDerive(0, None)
    cdi = mars.Derive(1, b'CompoundDeviceID')
    print('CDI1', cdi.hex())

    print('TSR test')
    sig = mars.Quote(1<<4, nonce, b'')
    mars.dump()
    print('TSR =', mars.RegRead(4).hex())

    # IDevID tests
    print('IDevID signature test')
    dig = hw.CryptHash(b'Initial Device Identity')
    sig = mars.Sign(b'IDevID', dig)
    print('Verified? ', 'Success' if mars.SignatureVerify(False, b'IDevID', dig, sig) else 'FAIL')

    if hw.CryptAkdf:
        pub = mars.PublicRead(True, b'')
        pem = pub.export_key(format='PEM')
        print('AKpub', pem)
        # pub = mars.PublicRead(True, b'ak2')
        # pub = mars.PublicRead(False, b'IDevID')
    mars.Unlock()
