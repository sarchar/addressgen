addressgen
==========

Addressgen is (going to be) a set of utilities to generate private keys and
their corresponding addresses for cryptocurrencies based on secp256k1. Currently,
only Bitcoin is supported, but in the future I will add support for others.

Requirements
============

Addressgen is tested on Linux and Windows, requires Python 3.3 and a copy of
libeay32.dll (Windows, obtained from OpensSL packages) or libssl.so (linux,
openssl package).

Usage
=====

Run "python3 genbtcaddress.py"

Arguments
---------

```
usage: genbtcaddress.py [-h] [-p PASSPHRASE] [-t] [-c] [-a STR] [-H HASH]

Generate Bitcoin Private Keys and Addresses

optional arguments:
  -h, --help            show this help message and exit
  -p PASSPHRASE, --passphrase PASSPHRASE
                        Use PASSPHRASE as the seed to a hash, the result of
                        the hash is used as the private key
  -t, --testnet         Generate testnet address
  -c, --compressed      Generate address using compressed private key
  -a STR, --address-only STR
                        Hash160 STR and produce a Bitcoin address; no
                        corresponding private key is generated
  -H HASH, --hash-type HASH
                        For -p only, specify the hash type to use [scrypt,
                        SHA256] (default: SHA-256)
```

Examples
--------

$ python3 genbtcaddress.py
```
ECDSA private key (random number / secret exponent) = e8458869c45ccf70a347dd9134b20081285232d283067bafca6b2949f5805b95
Bitcoin private key (Base58Check, uncompressed) = 5KaaeYWkztbF2XbTY1KM3v8GvM9kD5pj7F6UBR3QR2HDH5F3tkJ
------
ECDSA public key (uncompressed) = 04dd07e3c9b007b4931f2a964971540d8dfd293c4f2f7417ee3545a773d3777ac6662062af654df8342835d994ff150e298f2a97559961f5e48ece61e645570c46
Bitcoin Address (uncompressed): 1KdDSct7298zjvJpExvBHgUfXPEymFnfex (length=34)
```

$ python3 genbtcaddress.py -s "correct horse battery staple"
```
ECDSA private key (random number / secret exponent) = c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a
Bitcoin private key (Base58Check, uncompressed) = 5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS
------
ECDSA public key (uncompressed) = 0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455
Bitcoin Address (uncompressed): 1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T (length=34)
```

$ python3 genbtcaddress.py -t -c
```
ECDSA private key (random number / secret exponent) = 193303b923ade50f89659746c2cadfd6899bd04a83be669be7e3348354ff17b7
Bitcoin private key (Base58Check, compressed) = cNRgj5c4eLer2hgFoQhTxdn8u21SGGH1da8foW96NvPPA4srLSPn
------
ECDSA public key (compressed) = 032c2e370f4fa1a8da4c5ae1d14b1ed58c40cd5ce39ddc30f0c776784a311ea515
Bitcoin Address (compressed): mpefYwc3XE7Vt6bBEd4RHkSJRXni1dCNX7 (length=34)
```


