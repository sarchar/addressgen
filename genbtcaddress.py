#!/usr/bin/env python3
import argparse
import ctypes
import hashlib
import sys
from base58 import encode as base58_encode

################################################################################
################################################################################
DEBUG = False

################################################################################
################################################################################
try:
    ssl_library = ctypes.cdll.LoadLibrary('libeay32.dll')
except:
    ssl_library = ctypes.cdll.LoadLibrary('libssl.so')

if DEBUG:
    print("ssl_library is {}".format(ssl_library))

def bytes2hex(data):
    return ''.join([ '{:02x}'.format(v) for v in data ])

def hex2bytes(data):
    return bytes([ int(data[i:i+2], 16) for i in range(0, len(data), 2) ])

NID_secp160k1 = 708
NID_secp256k1 = 714

def gen_key_pair(curve_name=NID_secp256k1):
    k = ssl_library.EC_KEY_new_by_curve_name(curve_name)

    if ssl_library.EC_KEY_generate_key(k) != 1:
        raise Exception("internal error")

    bignum_private_key = ssl_library.EC_KEY_get0_private_key(k)
    size = (ssl_library.BN_num_bits(bignum_private_key)+7)//8

    if DEBUG:
        print("Private key size is {} bytes".format(size))

    storage = ctypes.create_string_buffer(size)
    ssl_library.BN_bn2bin(bignum_private_key, storage)
    private_key = storage.raw

    size = ssl_library.i2o_ECPublicKey(k, 0)

    if DEBUG:
        print("Public key size is {} bytes".format(size))

    storage = ctypes.create_string_buffer(size)
    ssl_library.i2o_ECPublicKey(k, ctypes.byref(ctypes.pointer(storage)))
    public_key = storage.raw

    ssl_library.EC_KEY_free(k)
    return public_key, private_key

def get_public_key(private_key, curve_name=NID_secp256k1):
    k = ssl_library.EC_KEY_new_by_curve_name(curve_name)
    
    storage = ctypes.create_string_buffer(private_key)
    bignum_private_key = ssl_library.BN_new()
    ssl_library.BN_bin2bn(storage, 32, bignum_private_key)

    group = ssl_library.EC_KEY_get0_group(k)
    point = ssl_library.EC_POINT_new(group)

    ssl_library.EC_POINT_mul(group, point, bignum_private_key, None, None, None)
    ssl_library.EC_KEY_set_private_key(k, bignum_private_key)
    ssl_library.EC_KEY_set_public_key(k, point)

    size = ssl_library.i2o_ECPublicKey(k, 0)
    storage = ctypes.create_string_buffer(size)
    pstorage = ctypes.pointer(storage)
    ssl_library.i2o_ECPublicKey(k, ctypes.byref(pstorage))
    public_key = storage.raw

    ssl_library.EC_POINT_free(point)
    ssl_library.BN_free(bignum_private_key)
    ssl_library.EC_KEY_free(k)
    return public_key

def compress(public_key):
    x_coord = public_key[1:33]
    if public_key[34] & 0x80:
        c = bytes([0x02]) + x_coord
    else:
        c = bytes([0x03]) + x_coord
    return c

def decompress(public_key):
    raise Exception("TODO")

def singlehash256(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()

def hash256(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    r = hasher.digest()

    hasher2 = hashlib.sha256()
    hasher2.update(r)
    return hasher2.digest()

def hash160(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    r = hasher.digest()

    hasher2 = hashlib.new('ripemd160')
    hasher2.update(r)
    return hasher2.digest()

def is_public_key(public_key):
    return len(public_key) > 0 and \
           ((public_key[0] == 0x04 and len(public_key) == 65) or \
            (public_key[0] in (0x02, 0x03) and len(public_key) == 3))

def address_from_data(data, version_byte=0):
    assert isinstance(data, bytes)
    return base58_check(hash160(data), version_byte=version_byte)

def base58_check(src, version_byte=0):
    src = bytes([version_byte]) + src

    r = hash256(src)

    if DEBUG:
        print('SHA256(SHA256(0x{:02x} + src)):'.format(version_byte), bytes2hex(r))

    checksum = r[:4]
    s = src + checksum
    
    if DEBUG:
        print('src + checksum:', bytes2hex(s))

    e = base58_encode(int.from_bytes(s, 'big'))
    if version_byte == 0:
        lz = 0
        while lz < len(src) and src[lz] == 0:
            lz += 1

        return ('1' * lz) + e
    return e

def parse_args():
    parser = argparse.ArgumentParser(description="Generate Bitcoin Private Keys and Addresses")
    parser.add_argument("-p", "--passphrase", default=None, help="Use PASSPHRASE as the seed to a hash, the result of the hash is used as the private key")
    parser.add_argument("-t", "--testnet", default=False, action='store_true', help="Generate testnet address")
    parser.add_argument("-c", "--compressed", default=False, action='store_true', help="Generate address using compressed private key")
    parser.add_argument("-a", "--address-only", metavar="STR", default=None, help="Hash160 STR and produce a Bitcoin address; no corresponding private key is generated")
    parser.add_argument("-H", "--hash-type", metavar="HASH", default='SHA256', help="For -p only, specify the hash type to use [scrypt, SHA256] (default: SHA-256)")

    args = parser.parse_args()
    if args.passphrase is not None and args.address_only is not None:
        raise Exception("you can not specify both -p and -a")
    if args.address_only is not None and args.compressed:
        raise Exception("you can not use -c with -a")
    return args

def main():
    args = parse_args()

    if args.passphrase is not None:
        if args.hash_type == "SHA256":
            private_key = singlehash256(args.passphrase.encode("utf8"))
        else:
            raise Exception("TODO")
        public_key = get_public_key(private_key)
    elif args.address_only is not None:
        if args.hash_type == "SHA256":
            public_key = args.address_only.encode("utf8")
        else:
            raise Exception("TODO")
        private_key = None
    else:
        public_key, private_key = gen_key_pair()

    if private_key is not None:
        print("ECDSA private key (random number / secret exponent) = {}".format(bytes2hex(private_key)))
        if args.compressed:
            print("Bitcoin private key (Base58Check, compressed) = {}".format(base58_check(private_key + bytes([0x01]), version_byte=239 if args.testnet else 128)))
        else:
            print("Bitcoin private key (Base58Check, uncompressed) = {}".format(base58_check(private_key, version_byte=239 if args.testnet else 128)))
        print('------')

    if public_key is not None:
        if args.compressed:
            compressed_public_key = compress(public_key)
            print("ECDSA public key (compressed) = {}".format(bytes2hex(compressed_public_key)))

            addr = base58_check(hash160(compressed_public_key), version_byte=111 if args.testnet else 0)
            print("Bitcoin Address (compressed): {} (length={})".format(addr, len(addr)))
        else:
            if args.address_only:
                print("Public key source = {}".format(bytes2hex(public_key)))
            else:
                print("ECDSA public key (uncompressed) = {}".format(bytes2hex(public_key)))

            addr = address_from_data(public_key, version_byte=111 if args.testnet else 0)
            print("Bitcoin Address (uncompressed): {} (length={})".format(addr, len(addr)))

if __name__ == "__main__":
    main()

