from stealth25519.ed25519 import point_decompress, secret_to_public, secret_expand


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
