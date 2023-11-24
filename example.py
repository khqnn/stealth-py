import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519

from stealth25519.key import PrivateKey, PublicKey
from stealth25519.address import StealthAddress
from stealth25519.generator import StealthAddressGenerator
from stealth25519.verifier import StealthAddressVerifier
from stealth25519.signer import StealthAddressSigner


def sha512(s):
    """
        This is our hash function to generate hash while generating or verifying stealth addresses. 
        Args:
            s (bytes): hash input as bytes

        Returns:
            bytes: Return a hash of input as bytes
    """
    return hashlib.sha512(s).digest()

# generate or load private key from cryptography or any other library as bytes array

private_spend_key_ = '6e2096a4aeb83752be2c2072d26d8c526c9bb7c5957289fc6feb85bd7da8dbf3'
private_view_key_ = ed25519.Ed25519PrivateKey.generate()

private_spend_key = PrivateKey(bytes.fromhex( private_spend_key_))
private_view_key = PrivateKey(private_view_key_.private_bytes_raw())

public_spend_key = private_spend_key.generatePublicKey()
public_view_key = private_view_key.generatePublicKey()

print('Private spend key: ', private_spend_key)
print('Private view key: ', private_view_key)
print('Public spend key: ', public_spend_key)
print('Public view key: ', public_view_key)


# generate stealth address

public_spend_key_bytes = bytes.fromhex('18a498c68461e39dd180745e5aa1faacbc9b8a5f74a7eb25b5038b66db0a4af6')
public_view_key_bytes = bytes.fromhex('b52c33b513c26e17b7105cb1ed1c7022ef00f3967aaac0ff8bd9d15ccee4d94e')

public_spend_key = PublicKey(public_spend_key_bytes)
public_view_key = PublicKey(public_view_key_bytes)

generator = StealthAddressGenerator(public_spend_key, public_view_key, hash_function = sha512)
stealth_address = generator.generate()
print('Stealth Address\n', stealth_address)

# Verify stealth address

private_view_key_bytes = bytes.fromhex('8cdc2d3879363eff3c187ee494c7154ac63a4b94c1814488fd46c4f2bafc2239')
public_spend_key_bytes = bytes.fromhex('18a498c68461e39dd180745e5aa1faacbc9b8a5f74a7eb25b5038b66db0a4af6')
R = bytes.fromhex('f694a725eade1f938797a87ba09d505f4be4358c1e8a865a3ef0ae202bb8b827')
P = bytes.fromhex('573fff985d6407e747a845ff9f6d245b65b68beb3738837d207943f7697a6338')

private_view_key = PrivateKey(private_view_key_bytes)
public_spend_key = PublicKey(public_spend_key_bytes)

stealth_address = StealthAddress(R, P)
verifier = StealthAddressVerifier(private_view_key, public_spend_key, hash_function = sha512)
results = verifier.verify(stealth_address)

print('Stealth address verified: ', results)

# Sign stealth address

private_spend_key_bytes = bytes.fromhex('da4956d53efc1c48472080ca284948399ef5dcb1feb47ebd5017330ca2416c30')
private_view_key_bytes = bytes.fromhex('8cdc2d3879363eff3c187ee494c7154ac63a4b94c1814488fd46c4f2bafc2239')
R = bytes.fromhex('f694a725eade1f938797a87ba09d505f4be4358c1e8a865a3ef0ae202bb8b827')
P = bytes.fromhex('573fff985d6407e747a845ff9f6d245b65b68beb3738837d207943f7697a6338')

private_spend_key = PrivateKey(private_spend_key_bytes)
private_view_key = PrivateKey(private_view_key_bytes)

msg = b'somedata'
stealth_address = StealthAddress(R, P)
signer = StealthAddressSigner(private_spend_key, private_view_key, hash_function = sha512)
sig = signer.sign(stealth_address, msg)
print('Stealth signature: ', sig.hex())


# Verify stealth address signature using standard Ed25519 algorithm

def verify_ed25519_signature(public_key_bytes, signature_bytes, message):
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature_bytes, message)
        return True
    except Exception as e:
        print(f"Signature verification failed: {str(e)}")
        return False

public_key_hex = '1d3796436ecf22b674f60990945fb09d4a5dd4ad6c16e04dd20ff46e71935fc5'
signature_hex = '56dcf17a9fd91b7d3d0dffc7ea86fd1cb1dda94caff964c2533c63ecd52166377684fa60f2cfe5258f9e5c8247db4e5003a73c1d0fbd42c56f31a7b996089404'
message = b'somedata'

public_key_bytes = bytes.fromhex(public_key_hex)
signature_bytes = bytes.fromhex(signature_hex)


verification_result = verify_ed25519_signature(public_key_bytes, signature_bytes, message)
print('Signature verification result:', verification_result)
