import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryp_to_go import AsymKey, CryptoHandler, KeyDerivationSetup
from cryp_to_go.core import hexlify, unhexlify


def demo_asym():
    import json
    from io import BytesIO
    # 1. create a file to be encrypted
    # 2. create an asymmetric keypair to exchange the encryption keys
    # 3. encrypt the file
    # 4. provide the encryption info
    # 5. decrypt
    path_private_key, path_public_key, path_to_encrypt = _prepare_demo()
    # encrypt, using generated symmetric keys and public key
    pubkey = AsymKey.from_pubkey_file(path_public_key)
    # signature key is optional
    handler = CryptoHandler.create_random(enable_signature_key=True)
    with open(path_to_encrypt + '.enc', 'wb+') as f_out:
        with open(path_to_encrypt, 'rb') as f_in:
            with handler.create_signature():
                for chunk in handler.encrypt_stream(f_in):
                    f_out.write(chunk)
        f_out.seek(0)
        print('encrypted (first 20):', binascii.hexlify(f_out.read(20)).decode())
    # exchange only enc_info (JSONifiable)
    decrypt_info = handler.to_decrypt_info(pubkey)
    del pubkey
    del handler
    print(json.dumps(decrypt_info, indent=4))
    # decrypt, using symmetric keys retrieved via private key
    privkey = AsymKey.privkey_from_pemfile(path_private_key)
    buffer = BytesIO()  # use BytesIO instead of yet another file
    with CryptoHandler.decryptor_from_info(decrypt_info, privkey) as handler:
        with open(path_to_encrypt + '.enc', 'rb') as f_in:
            for chunk in handler.decrypt_stream(f_in):
                buffer.write(chunk)
    buffer.seek(0)
    decrypted = buffer.read().decode()
    assert decrypted == 'The cake is a lie!\n' * 10000
    import os
    for path in [path_private_key, path_public_key, path_to_encrypt]:
        os.remove(path)


def _prepare_demo():
    import os
    import tempfile
    from cryptography.hazmat.primitives.asymmetric import rsa

    # create temporary file and close
    def _touch():
        fd, path = tempfile.mkstemp()
        os.close(fd)
        return path

    # create file to encrypt
    path_to_encrypt = _touch()
    with open(path_to_encrypt, 'w') as f_out:
        f_out.write('The cake is a lie!\n' * 10000)
    # generate a keypair
    asym_key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    path_private_key = _touch()
    with open(path_private_key, 'wb') as f_out:
        f_out.write(
            asym_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
        )
    path_public_key = _touch()
    with open(path_public_key, 'wb') as f_out:
        f_out.write(
            asym_key.public_key().public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH
            )
        )
    return path_private_key, path_public_key, path_to_encrypt


def demo_sym():
    import os
    from io import BytesIO
    path_private_key, path_public_key, path_to_encrypt = _prepare_demo()
    # we don't need the keypair
    os.remove(path_private_key)
    os.remove(path_public_key)
    # pick any password
    password = "supersecret".encode()
    # enable_signature_key is optional
    key_setup = KeyDerivationSetup.create_default(enable_signature_key=True)
    handler = key_setup.generate_keys(password)
    with open(path_to_encrypt + '.enc', 'wb+') as f_out:
        with open(path_to_encrypt, 'rb') as f_in:
            with handler.create_signature():
                for chunk in handler.encrypt_stream(f_in):
                    f_out.write(chunk)
            f_out.seek(0)
            print('encrypted (first 20):', binascii.hexlify(f_out.read(20)).decode())
    # store public information
    signature = hexlify(handler.signature)  # for validation
    key_setup_dict = key_setup.to_dict()
    # remove handler
    del handler
    del key_setup
    # decrypt
    handler = KeyDerivationSetup.from_dict(key_setup_dict).generate_keys(password)
    # use BytesIO instead of yet another file
    buffer = BytesIO()
    with open(path_to_encrypt + '.enc', 'rb') as f_in:
        with handler.verify_signature(unhexlify(signature)):
            for chunk in handler.decrypt_stream(f_in):
                buffer.write(chunk)
    buffer.seek(0)
    decrypted = buffer.read().decode()
    assert decrypted == 'The cake is a lie!\n' * 10000
    os.remove(path_to_encrypt)


if __name__ == '__main__':
    demo_asym()
    demo_sym()
