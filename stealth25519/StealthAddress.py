from stealth25519.ed25519 import *
from stealth25519.ed25519 import G, _sign
import random

p, q = get25519Params()

class PublicKey:
    """
    Represents a public key for Ed25519-based cryptography.

    Attributes:
        publicBytes (bytes): The raw bytes of the public key.
        B (Point): The point on the curve corresponding to the public key.

    Methods:
        getPublicBytes(): Get the raw bytes of the public key.
        getPointOnCurve(): Get the point on the curve corresponding to the public key.
        __str__(): Return a hexadecimal representation of the public key.
    """

    def __init__(self, publicBytes = None):
        """
        Initialize a PublicKey instance.

        Args:
            publicBytes (bytes): The raw bytes of the public key.
        """

        self.publicBytes = publicBytes
        self.B = point_decompress(publicBytes)

    def getPublicBytes(self):
        """Get the raw bytes of the public key."""

        return self.publicBytes

    def getPointOnCurve(self):
        """Get the point on the curve corresponding to the public key."""

        return self.B

    def __str__(self):
        """Return a hexadecimal representation of the public key."""

        return self.publicBytes.hex()



class PrivateKey:
    """
    Represents a private key for Ed25519-based cryptography.

    Attributes:
        privateBytes (bytes): The raw bytes of the private key.
        b (int): The private scalar used in key generation.
        publicKey (PublicKey): The corresponding public key.

    Methods:
        generatePublicKey(): Generate the corresponding public key.
        getPrivateBytes(): Get the raw bytes of the private key.
        __str__(): Return a hexadecimal representation of the private key.
    """

    def __init__(self, privateBytes = None):
        """
        Initialize a PrivateKey instance.

        Args:
            privateBytes (bytes): The raw bytes of the private key.
        """

        publicBytes = secret_to_public(privateBytes) # ed25519
        b, dummy = secret_expand(privateBytes) # ed25519
        
        self.privateBytes = privateBytes
        self.b = b
        self.publicKey = PublicKey(publicBytes)

    def generatePublicKey(self):
        """Generate the corresponding public key."""

        return self.publicKey

    def getPrivateBytes(self):
        """Get the raw bytes of the private key."""

        return self.privateBytes

    def __str__(self):
        """Return a hexadecimal representation of the private key."""

        return self.privateBytes.hex()



class StealthAddress:
    """
    Represents a Stealth Address for Ed25519-based cryptography.

    Attributes:
        Rs (bytes): The raw bytes of the compressed R point.
        Ps (bytes): The raw bytes of the compressed P point.
        R (Point): The decompressed R point.

    Methods:
        __str__(): Return a formatted string representation of the Stealth Address.
    """

    def __init__(self, R = None, P = None):
        """
        Initialize a StealthAddress instance.

        Args:
            R (bytes): The raw bytes of the compressed R point.
            P (bytes): The raw bytes of the compressed P point.
        """

        self.Rs = R
        self.Ps = P
        self.R = point_decompress(R) # ed25519
    
    def __str__(self):
        """Return a formatted string representation of the Stealth Address."""

        return f'R: {self.Rs.hex()}\nP: {self.Ps.hex()}'



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

