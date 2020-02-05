import sys
import os.path
import argparse
import getpass
from typing import Union, NoReturn
from .interface import SQLiteFileInterface
from .core import AsymKey, CryptoHandler


class SQLiteCLI:

    def __init__(
            self,
            filename: str,
            asym_key_public: Union[None, str] = None,
            asym_key_private: Union[None, str] = None,
    ):
        self.filename: str = filename
        self.new_file: bool = not os.path.exists(self.filename)
        self._interface: Union[None, SQLiteFileInterface] = None
        self.asym_key_private = asym_key_private
        self.asym_key_public = asym_key_public
        self._pubkey: Union[None, str] = None
        self._private_key: Union[None, str] = None

    @property
    def interface(self) -> SQLiteFileInterface:
        if self._interface is None:
            self._interface = SQLiteFileInterface(self.filename)
        return self._interface

    @property
    def pubkey(self) -> Union[None, AsymKey]:
        key_str = self.asym_key_public
        if key_str is None:
            return None
        if self._pubkey is None:
            key = self.load_pubkey(key_str)
            self._pubkey = key
        return self._pubkey

    @staticmethod
    def load_pubkey(key_str: str) -> AsymKey:
        try:
            key = AsymKey.from_pubkey_string(key_str)
        except ValueError as exc:
            if 'not in the proper format' not in exc.args[0]:
                raise
            key = AsymKey.from_pubkey_file(key_str)
        return key

    @property
    def private_key(self) -> Union[None, AsymKey]:
        if self.asym_key_private is None:
            return None
        if self._private_key is None:
            self._private_key = AsymKey.privkey_from_pemfile(
                self.asym_key_private,
                getpass.getpass('Passphrase for private key: ').encode()
            )
        return self._private_key

    def get_read_access(self) -> None:
        if self.new_file:
            fail('storage file %s does not exist' % self.filename)
        if self.private_key is not None:
            self.interface.load_crypto_handler_async(self.private_key)
        elif self.interface.has_key_derivation_info():
            self.interface.load_crypto_handler(getpass.getpass('Password for key derivation: ').encode())
        else:
            fail('Neither public key nor key derivation settings present for read access.')

    def get_write_access(self, always_derive: bool = False) -> None:
        if not self.new_file:
            # read access provides everything necessary
            if not self.interface.has_key_derivation_info() and always_derive:
                fail('key derivation can not be added to existing file.')
            self.get_read_access()
        else:
            # either pubkey or key derivation or both
            if self.pubkey is None or always_derive:
                self.interface.use_new_crypto_handler(getpass.getpass('Password for key derivation: ').encode())
            else:
                self.interface.crypto_handler = CryptoHandler.create_random()
            if self.pubkey is not None:
                self.interface.store_keys_asymmetric(self.pubkey)

    def append_key(self, key: AsymKey = None) -> None:
        key = key or self.pubkey
        if key is None:
            fail('No public key given for appending.')
        self.interface.store_keys_asymmetric(key)


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='encrypt/decrypt files',
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', '-e', action='store_true', help='encrypt target file(s)')
    group.add_argument('--decrypt', '-d', action='store_true', help='decrypt target file(s)')
    group.add_argument('--list', '-l', action='store_true', help='list content of encypted storage')
    parser.add_argument(
        '--pubkey',
        '-p',
        type=str,
        help='public SSL key file for write/encryption access.',
    )
    parser.add_argument(
        '--private_key',
        '-k',
        type=str,
        help='PEM file with private SSL key for read/decrypt access.',
    )
    parser.add_argument('--storage_file', '-s', type=str, default='cryp-to-go-safe.sqlite',
                        help='storage file to use.')
    parser.add_argument('--always_derive', action='store_true',
                        help='encryption only: new keys are created from a password even if a public key is provided')
    parser.add_argument('--append_key', type=str, default=None,
                        help='enable access via given key pair (no duplicate check)')
    parser.add_argument('files', nargs=argparse.REMAINDER)
    return parser


def fail(msg: str) -> NoReturn:
    sys.exit(msg)


def main() -> None:
    parser = get_parser()
    opts = parser.parse_args()
    handler = SQLiteCLI(
        filename=opts.storage_file,
        asym_key_public=opts.private_key,
        asym_key_private=opts.pubkey
    )
    decrypt_action = opts.decrypt or opts.list
    if decrypt_action:
        handler.get_read_access()
    else:
        handler.get_write_access(opts.always_derive)
    if opts.append_key:
        handler.append_key(handler.load_pubkey(opts.append_key))
    files = opts.files
    if opts.encrypt:
        print(handler.interface.store_files(opts.files))
    elif opts.decrypt:
        print(handler.interface.restore_files(files))
    elif opts.list:
        for doc in handler.interface.read_file_index():
            print(doc['path'])
