from stealth25519.ed25519 import *
from stealth25519.ed25519 import G, _sign
import random

p, q = get25519Params()

class PublicKey:
    def __init__(self, publicBytes = None):
        self.publicBytes = publicBytes
        self.B = point_decompress(publicBytes)

    def getPublicBytes(self):
        return self.publicBytes

    def getPointOnCurve(self):
        return self.B

    def __str__(self):
        return self.publicBytes.hex()



class PrivateKey:
    def __init__(self, privateBytes = None):
        publicBytes = secret_to_public(privateBytes) # ed25519
        b, dummy = secret_expand(privateBytes) # ed25519
        
        self.privateBytes = privateBytes
        self.b = b
        self.publicKey = PublicKey(publicBytes)

    def generatePublicKey(self):
        return self.publicKey

    def getPrivateBytes(self):
        return self.privateBytes

    def __str__(self):
        return self.privateBytes.hex()



class StealthAddress:
    def __init__(self, R = None, P = None):
        self.Rs = R
        self.Ps = P
        self.R = point_decompress(R) # ed25519
        self.address = R + P
    
    def __str__(self):
        return f'R: {self.Rs.hex()}\nP: {self.Ps.hex()}'



class StealthAddressGenerator:
    def __init__(self, publicSpendKey = None, publicViewKey = None):
        self.publicSpendKey = publicSpendKey
        self.publicViewKey = publicViewKey
        self.V = point_decompress(publicViewKey.getPublicBytes()) # ed25519
        self.B = point_decompress(publicSpendKey.getPublicBytes()) # ed25519
        
    def generate(self):
        r = sha512_modq(random.randbytes(32))
        R = point_mul(r, G)
        Rs = point_compress(R)
    
        f = point_compress(point_mul(r, self.V))
        h = sha512_modq(f) # ed25519
        P = point_add(point_mul(h, G), self.B)
        Ps = point_compress(P)
        
        return StealthAddress(Rs, Ps)



class StealthAddressVerifier:
    def __init__(self, privateViewKey, publicSpendKey):
        self.privateViewKey = privateViewKey
        self.publicSpendKey = publicSpendKey
        vs, dummy = secret_expand(privateViewKey.getPrivateBytes()) # ed25519
        self.vs = vs
        self.B = publicSpendKey.getPointOnCurve()


    def verify(self, stealthAddress):
        Rs, Ps = stealthAddress.Rs, stealthAddress.Ps
        f = point_compress(point_mul(self.vs, stealthAddress.R)) # ed25519
        h_ = sha512_modq(f) # ed25519
        P_ = point_add(point_mul(h_, G), self.B) # ed25519
        Ps_ = point_compress(P_) # ed25519
        return Ps==Ps_


class StealthAddressSigner:
    def __init__(self, privateSpendKey, privateViewKey):
        self.privateSpendKey = privateSpendKey
        self.privateViewKey = privateViewKey
        bs, dummy = secret_expand(privateSpendKey.getPrivateBytes()) # ed25519
        vs, dummy = secret_expand(privateViewKey.getPrivateBytes()) # ed25519
        self.bs = bs
        self.vs = vs

    def sign(self, stealthAddress, msg):
        R, Ps =stealthAddress.R, stealthAddress.Ps
        f = point_compress(point_mul(self.vs, R)) # ed25519
        h = sha512_modq(f)  # ed25519
        sk = (h + self.bs) % q
        pk = point_mul(sk, G) # ed25519
        pk = point_compress(pk) # ed25519
        if pk!=Ps:
            raise Exception("Not a valid transaction")
    
        prefix = sha256(sk.to_bytes(32, 'little')) # ed25519
        return _sign(sk, prefix, msg) # ed25519

