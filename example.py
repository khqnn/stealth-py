from cryptography.hazmat.primitives.asymmetric import ed25519
from stealth25519.StealthAddress import PrivateKey, PublicKey, StealthAddress, StealthAddressGenerator, StealthAddressVerifier, StealthAddressSigner

# generate or load private key from cryptography or any other library as bytes array

private_spend_key = '6e2096a4aeb83752be2c2072d26d8c526c9bb7c5957289fc6feb85bd7da8dbf3'
private_view_key = ed25519.Ed25519PrivateKey.generate()

privateSpendKey = PrivateKey(bytes.fromhex( private_spend_key))
privateViewKey = PrivateKey(private_view_key.private_bytes_raw())

publicSpendKey = privateSpendKey.generatePublicKey()
publicViewKey = privateViewKey.generatePublicKey()

print('Private spend key: ', privateSpendKey)
print('Private view key: ', privateViewKey)
print('Public spend key: ', publicSpendKey)
print('Public view key: ', publicViewKey)


# generate stealth address

publicSpendKeyBytes = bytes.fromhex('18a498c68461e39dd180745e5aa1faacbc9b8a5f74a7eb25b5038b66db0a4af6')
publicViewKeyBytes = bytes.fromhex('b52c33b513c26e17b7105cb1ed1c7022ef00f3967aaac0ff8bd9d15ccee4d94e')

publicSpendKey = PublicKey(publicSpendKeyBytes)
publicViewKey = PublicKey(publicViewKeyBytes)

stealthAddressGenerator = StealthAddressGenerator(publicSpendKey, publicViewKey)
stealthAddress = stealthAddressGenerator.generate()
print('Stealth Address\n', stealthAddress)

# Verify stealth address

privateViewKeyBytes = bytes.fromhex('8cdc2d3879363eff3c187ee494c7154ac63a4b94c1814488fd46c4f2bafc2239')
publicSpendKeyBytes = bytes.fromhex('18a498c68461e39dd180745e5aa1faacbc9b8a5f74a7eb25b5038b66db0a4af6')
R = bytes.fromhex('72e46affe404d301b2546ac420a209929e98120526b677b9576fd4f687691b51')
P = bytes.fromhex('f5ec778dfcf57e8b736729efdcbb458110e814c8bec4ef5667e2d7571cbbc8c4')

privateViewKey = PrivateKey(privateViewKeyBytes)
publicSpendKey = PublicKey(publicSpendKeyBytes)

stealthAddress = StealthAddress(R, P)
stealthAddressVerifier = StealthAddressVerifier(privateViewKey, publicSpendKey)
results = stealthAddressVerifier.verify(stealthAddress)

print('Stealth address verified: ', results)

# Sign stealth address

privateSpendKeyBytes = bytes.fromhex('da4956d53efc1c48472080ca284948399ef5dcb1feb47ebd5017330ca2416c30')
privateViewKeyBytes = bytes.fromhex('8cdc2d3879363eff3c187ee494c7154ac63a4b94c1814488fd46c4f2bafc2239')
R = bytes.fromhex('8a7b9c5bbce1ddb29893bbf96bd3a278d9f4576018c384c1d2f337012607cc1c')
P = bytes.fromhex('1d3796436ecf22b674f60990945fb09d4a5dd4ad6c16e04dd20ff46e71935fc5')

privateSpendKey = PrivateKey(privateSpendKeyBytes)
privateViewKey = PrivateKey(privateViewKeyBytes)

msg = b'somedata'
stealthAddress = StealthAddress(R, P)
stealthAddressSigner = StealthAddressSigner(privateSpendKey, privateViewKey)
sig = stealthAddressSigner.sign(stealthAddress, msg)
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
