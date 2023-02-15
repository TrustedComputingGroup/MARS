# MARS Python Emulator

**WARNING** - the code found here is for an informative reference only. There is no assertion of correctenss of the algorithms used
nor with compliance to any specification. Two major departuers from the specification are:

- Instead of Response Codes being returned, exceptions are generated.
- Parameters and returned values are different to better align with Python than with C.

## Dependencies

- pip
- pip install pycryptodome
- pip install ascon
- pip install cbor2

## Crypto Hardware

While MARS itself is crypto agnostic, it is instantiated with
underlying "crypto hardware" using one of the modules shown. 

| NAME.py  | HASH       | SKDF          | AKDF | SIGN
| :---     | :---       | :---          | :--- | :--- 
| hw_ascon | Ascon Hash | AEAD Tag      | -    | AEAD Tag
| hw_ecc   | SHA-256    | DRBG          | ECC  | ECDSA
| hw_sha2  | SHA-256    | TPM KDFa      | -    | HMAC
| hw_sha3  | SHA3-256   | 800-108 KMAC  | -    | KMAC
| hw_she   | AES-MP     | 800-108 lite  | -    | CMAC

MP = Miyaguchi-Preneel compression algorithm

## Sample Usage

```python
$ python3
>>> from mars import MARS_RoT
>>> import hw_sha2 as hw
>>> secret = b'Here are thirty two secret bytes'
>>> mars = MARS_RoT(hw, secret, 4)
>>> mars.Lock()
>>> mars.SequenceHash()
>>> mars.SequenceUpdate(b'some bytes')
>>> dig = mars.SequenceComplete()
>>> dig.hex()
'0d22cdcc10e6d049dbe1af5123d50873fdfc1a4f58306e58cb6241be9472014d'
>>> mars.PcrExtend(0, dig)
>>> sig = mars.Quote(0b0001, b'challenge', b'AK1')
>>> sig.hex()
'2bfa1a34ac87851fd750ff6edf3643e1bb8fb7cc71f7912c0a6b3043d18ce89d'
>>> pcr = mars.RegRead(0)
>>> pcr.hex()
'454cd4bc75e2ab9d314b8f6911cfb51f479f1850b565c33e8ffa1276feb8a2da'
>>> mars.Unlock()
```

## References

- [ MARS Library Specification ]( https://trustedcomputinggroup.org/resource/mars-library-specification/ )
- [ Ascon ]( https://ascon.iaik.tugraz.at )
- [ CBOR2 ]( https://github.com/agronholm/cbor2 )
- [ AUTOSAR SHE ]( https://www.autosar.org/fileadmin/standards/foundation/22-11/AUTOSAR_TR_SecureHardwareExtensions.pdf )
- [ Miyaguchi-Preneel compression algorithm ]( https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi–Preneel )

