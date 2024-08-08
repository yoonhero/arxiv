from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.ellipticcurve import *
import hashlib
from random import SystemRandom
from binascii import hexlify
from struct import Struct

n = SECP256k1.order
#Generator
x1 = 55066263022277343669578718895168534326250603453777594175500187360389116729240
y1 = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = Point(SECP256k1.curve, x1, y1)

# https://bitcoin.stackexchange.com/questions/13970/python-code-to-generate-private-ecdsa-key
SYS_RAN = SystemRandom()
PACKER = Struct('>QQQQ')
MIN_VAL = 1
MAX_VAL = n
def mkprivkey():
    key = SYS_RAN.randint(MIN_VAL, MAX_VAL)
    key0 = key >> 192
    key1 = (key >> 128) & 0xffffffffffffffff
    key2 = (key >> 64) & 0xffffffffffffffff
    key3 = key & 0xffffffffffffffff

    return int(hexlify(PACKER.pack(key0, key1, key2, key3)), 16)

class Wallet():
    def __init__(self):
        self._k = self.create_random_key()

    def create_random_key(self): return mkprivkey()
    def public_key(self): return G*self._k

    def sign(self, msg: bytes, l, P, R):
        #message hash
        hash_obj = hashlib.sha256(f"{P}-{R}-{msg}".encode("utf-8"))
        hash_hex = hash_obj.hexdigest()
        z = int(hash_hex, 16)
        s = (l+z*self._k) % n
        return s, z

    @staticmethod
    def validate(P, R, z, s):
        return R + z*P == s*G

    @staticmethod
    def combine_keys(keys):
        p = keys[0]
        for key in keys[1:]: p+=key
        return p

def group_sign(wallets: list[Wallet]):
    public_keys = [wallet.public_key() for wallet in wallets]
    random_keys = [wallet.create_random_key() for wallet in wallets]

    P = Wallet().combine_keys(public_keys)
    R = G * sum(random_keys)

    s = None
    z = None
    for wallet, random_key in zip(wallets, random_keys):
        _s, z = wallet.sign(f"{len(wallets)}", random_key, P, R)
        if s != None:
            s += _s
        else: s = _s
    
    print(wallet.validate(P, R, z, s))

    return s, z

if __name__ == "__main__":
    wallets = [Wallet() for _ in range(5)]

    group_sign(wallets)


    
        