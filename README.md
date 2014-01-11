addressgen
==========

Addressgen is a utility to generate private keys and their corresponding
addresses for cryptocurrencies based on secp256k1. Currently, only Bitcoin,
Dogecoin, and Litecoin are supported, but in the future I will add support for
more.

Requirements
============

Addressgen is tested on Linux and Windows, requires Python 3.3 and a copy of
libeay32.dll (Windows, obtained from OpensSL packages) or libssl.so (linux,
openssl package).

Usage
=====

Run "python3 genaddress.py"

Arguments
---------

```
usage: genaddress.py [-h] [-p PASSPHRASE] [-t] [-c] [-a STR] [-H HASH]
                     [-k KEY] [-e KEY] [-n COIN]

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
  -k KEY, --private-key KEY
                        Generate the public key and address from the given
                        Bitcoin private key
  -e KEY, --bip32-private-key KEY
                        Generate the BIP32 public key and show information
                        from the Bitcoin extended private key
  -n COIN, --coin COIN  Generate an address for the given coin (BTC, DOGE,
                        LTC) [default: BTC]
```

Examples
--------

$ python3 genaddress.py
```
ECDSA private key (random number / secret exponent)
    f4ad2e9b13b3ffa97b7e3e5eaf5ec94b4da429b8412d9e5c45ec05b5354e58cb
Bitcoin private key (Base58Check, uncompressed)
    5Kg3Wmk3X9KWqgevmGpzUmMRu84tiLy6oASRiYstWp88aPU1bCt
Bitcoin extended private key (Base58Check)
    xprv9s21ZrQH143K37B9jFanMBoYpPDtyAEZyPa39PEEnk6nZkznRH128dsCoeKqwF9wdYoSdZWGMzykeZEuGt7vK5YRzvYcArN9mPYMdSBc8Pg
    (embedded private key) -> KyFTr25dLy2JCUcjWaEUzgsK6T2ZJjMZnmCRxqLu7AC4HnHYJPa2
------
ECDSA public key (uncompressed)
    04e20d0909e0096269ddaaf052e01ba84c0d306ea76ca76006095077ec627904eb609fc41c462a9d213d7a2f379c15f8f3eb7de09b9b600779e08970e22eb6f92b
Bitcoin Address (uncompressed, length=34):
    13zTsvwJyDu1J3YzcH9monB34n7TTRWgeg
Bitcoin extended public key
    xpub661MyMwAqRbcFbFcqH7niKkHNR4PNcxRLcVdwmdrM5dmSZKvxpKGgSBgewbCupkSveARVgALUn5E3CT6kGd1A9TrUKwBeUnEkZMt6dg6HsH
    (embedded public key) -> 0362d6b5bce1ea8e4db415e9ae5a66261ce7d9a86515f2a79b1dc04127acba5ea8
    (bitcoin address) -> 12GonQ6PrwCkxPHJ6RCSh7Hfc9RGy1oGXQ
```

$ python3 genaddress.py -p "correct horse battery staple"
```
ECDSA private key (random number / secret exponent)
    c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a
Bitcoin private key (Base58Check, uncompressed)
    5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS
Bitcoin extended private key (Base58Check)
    xprv9s21ZrQH143K2yLSxbXemfny4nZroqhpiXEQ1MYx8vo2k7HRXypsWesNr7GkWTuU9CeaW7QeR38NjjaSfZBAAZVkVEpXwEkxLLXP2q1iFUd
    (embedded private key) -> KwyNQchak8YmPrMjiZubCDbTGupAFPjQGp2A1mE2feyEkgjhPzNF
------
ECDSA public key (uncompressed)
    0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455
Bitcoin Address (uncompressed, length=34):
    1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T
Bitcoin extended public key
    xpub661MyMwAqRbcFTQv4d4f8ojhcpQMDJRg5k9zojxZhGL1cuca5X984TBrhQw9ZJnvDdzsrjWG8nv4fsWjSU9HpX7pR3RKh2mezryhwXqvkF3
    (embedded public key) -> 0371070e700787e78e1810b2843c0723fcf25643f9de9bb90fca95ca2941dd485c
    (bitcoin address) -> 1HW5NtrRYqmvvF36hxvGFf7e4F2voLyVk2
```

$ python3 genaddress.py -t -c
```
ECDSA private key (random number / secret exponent) = 193303b923ade50f89659746c2cadfd6899bd04a83be669be7e3348354ff17b7
Bitcoin private key (Base58Check, compressed) = cNRgj5c4eLer2hgFoQhTxdn8u21SGGH1da8foW96NvPPA4srLSPn
------
ECDSA public key (compressed) = 032c2e370f4fa1a8da4c5ae1d14b1ed58c40cd5ce39ddc30f0c776784a311ea515
Bitcoin Address (compressed): mpefYwc3XE7Vt6bBEd4RHkSJRXni1dCNX7 (length=34)
```


$ python3 genaddress.py -n doge
```
ECDSA private key (random number / secret exponent)
    72d876e931495e83482c575ce99c2355c9ce242976d489935c34ba4bd6fc86a9
Bitcoin private key (Base58Check, uncompressed)
    6K1CT2vQjWQqKVR83xUY2cLzZDojKVSPhi3yUqrUL59XnwxDhQ7
Bitcoin extended private key (Base58Check)
    dgpv51eADS3spNJh7xXDGiYLiPjsomczzck2vxCJ929t2qPi1SPTgtScNG963iNTCzNabkVNDF2gVAiVtEo6Xwq61bHwshRC4bvQU9y2TBf2Bge
    (embedded private key) -> L3F32GWcXPY2ooBxmZPiCmaXBihwN1rrZy5iHNdvFxPC6NCRGZKE
------
ECDSA public key (uncompressed)
    04f9007f31df0a377200f3ec469d3c7140fe3808de89ef24d433ebcd94f0ef14a1839307e0049e132f724d471fd979d6f983a5989762af66c5dce94c7ae9a8f6d8
Bitcoin Address (uncompressed, length=34):
    DEbTByGXqsEjy6mUUk1LwP5DaCGDxPRJRa
Bitcoin extended public key
    dgub8kXBZ7ymNWy2QpBNJxAJqFHUGKzdpjmkDYyWJ8YrpxSiZVWA6ezP1ZYjcvgHpjwXGxUkXQbpTtUMC4Lande7fVN22kp64r8F9ywDQbd6C2d
    (embedded public key) -> 0261cd3c99394838b3202df2db8e16c958d2bc91d4dc913fa4234d1ed89b0c5c7b
    (bitcoin address) -> DDJmbxNnCvCp4ZQD5FtNpd698XNqykRzri
```
