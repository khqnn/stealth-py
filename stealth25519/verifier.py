from stealth25519.ed25519 import get25519Params, secret_expand, point_compress, sha512_modq, point_add, point_mul

p, q, G = get25519Params()

class StealthAddressVerifier:
    """
    Verifies Stealth Addresses for Ed25519-based cryptography.

    Attributes:
        privateViewKey (PrivateKey): The private view key.
        publicSpendKey (PublicKey): The public spend key.
        vs (int): The expanded private view key scalar.
        B (Point): The decompressed point corresponding to the public spend key.

    Methods:
        verify(stealthAddress): Verify the given Stealth Address.
    """

    def __init__(self, privateViewKey, publicSpendKey):
        """
        Initialize a StealthAddressVerifier instance.

        Args:
            privateViewKey (PrivateKey): The private view key.
            publicSpendKey (PublicKey): The public spend key.
        """

        self.privateViewKey = privateViewKey
        self.publicSpendKey = publicSpendKey
        vs, dummy = secret_expand(privateViewKey.getPrivateBytes()) # ed25519
        self.vs = vs
        self.B = publicSpendKey.getPointOnCurve()


    def verify(self, stealthAddress):
        """Verify the given Stealth Address.

        Args:
            stealthAddress (StealthAddress): The Stealth Address to be verified.
        """

        Rs, Ps = stealthAddress.Rs, stealthAddress.Ps
        f = point_compress(point_mul(self.vs, stealthAddress.R)) # ed25519
        h_ = sha512_modq(f) # ed25519
        P_ = point_add(point_mul(h_, G), self.B) # ed25519
        Ps_ = point_compress(P_) # ed25519
        return Ps==Ps_

