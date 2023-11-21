from cryptography.hazmat.primitives.asymmetric import ed25519
from StealthAddress import PrivateKey, PublicKey, StealthAddress, StealthAddressGenerator, StealthAddressVerifier, StealthAddressSigner

if __name__=="__main__": 
    # Load private key from any library and get public key from private key

    from StealthAddress import PrivateKey

    private_spend_key = ed25519.Ed25519PrivateKey.generate()
    private_view_key = ed25519.Ed25519PrivateKey.generate()

    privateSpendKey = PrivateKey(private_spend_key.private_bytes_raw())
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
    R = bytes.fromhex('616fc339399d17f0946035f86fe3d6ba654d1d0a029faad3d48278c18f93b121')
    P = bytes.fromhex('0435a7ae757a08a28fd4d70a85e67ba3feed7b677f519d133d54a5c57680b3e2')

    privateSpendKey = PrivateKey(privateSpendKeyBytes)
    privateViewKey = PrivateKey(privateViewKeyBytes)

    msg = b'somedata'
    stealthAddress = StealthAddress(R, P)
    stealthAddressSigner = StealthAddressSigner(privateSpendKey, privateViewKey)
    sig = stealthAddressSigner.sign(stealthAddress, msg).hex()
    print('Stealth signature: ', sig)