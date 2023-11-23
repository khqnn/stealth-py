from stealth25519.ed25519 import get25519Params, _sign, secret_expand, point_compress, sha512_modq, point_mul, sha256

p, q, G = get25519Params()

class StealthAddressSigner:
    """
    Signs Stealth Addresses for Ed25519-based cryptography.

    Attributes:
        privateSpendKey (PrivateKey): The private spend key.
        privateViewKey (PrivateKey): The private view key.
        bs (int): The expanded private spend key scalar.
        vs (int): The expanded private view key scalar.

    Methods:
        sign(stealthAddress, msg): Sign the given Stealth Address and message.

    Returns:
        bool: True if the transaction is intended for the recipient
    """

    def __init__(self, privateSpendKey, privateViewKey):
        """
        Initialize a StealthAddressSigner instance.

        Args:
            privateSpendKey (PrivateKey): The private spend key.
            privateViewKey (PrivateKey): The private view key.
        """

        self.privateSpendKey = privateSpendKey
        self.privateViewKey = privateViewKey
        bs, dummy = secret_expand(privateSpendKey.getPrivateBytes()) # ed25519
        vs, dummy = secret_expand(privateViewKey.getPrivateBytes()) # ed25519
        self.bs = bs
        self.vs = vs

    def sign(self, stealthAddress, msg):
        """Sign the given Stealth Address and message.

        Args:
            stealthAddress (StealthAddress): The Stealth Address to be signed.
            msg (bytes): The message to be signed.

        Returns:
            str: The hexadecimal representation of the signature.
        """

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

