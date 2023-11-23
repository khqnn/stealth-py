from stealth25519.ed25519 import point_decompress


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

