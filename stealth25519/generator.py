from stealth25519.ed25519 import get25519Params, point_compress, point_decompress, sha512_modq, point_mul, point_add
from stealth25519.address import StealthAddress
import random

p, q, G = get25519Params()


class StealthAddressGenerator:
    """
    Generates Stealth Addresses for Ed25519-based cryptography.

    Attributes:
        publicSpendKey (PublicKey): The public spend key.
        publicViewKey (PublicKey): The public view key.
        V (Point): The decompressed point corresponding to the public view key.
        B (Point): The decompressed point corresponding to the public spend key.

    Methods:
        generate(): Generate a Stealth Address.
    """

    def __init__(self, publicSpendKey = None, publicViewKey = None):
        """
        Initialize a StealthAddressGenerator instance.

        Args:
            publicSpendKey (PublicKey): The public spend key.
            publicViewKey (PublicKey): The public view key.
        """

        self.publicSpendKey = publicSpendKey
        self.publicViewKey = publicViewKey
        self.V = point_decompress(publicViewKey.getPublicBytes()) # ed25519
        self.B = point_decompress(publicSpendKey.getPublicBytes()) # ed25519
        
    def generate(self):
        """Generate a Stealth Address."""

        r = sha512_modq(random.randbytes(32))
        R = point_mul(r, G)
        Rs = point_compress(R)
    
        f = point_compress(point_mul(r, self.V))
        h = sha512_modq(f) # ed25519
        P = point_add(point_mul(h, G), self.B)
        Ps = point_compress(P)
        
        return StealthAddress(Rs, Ps)


