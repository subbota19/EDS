from Crypto.PublicKey import RSA

import os

FORMAT_ENCODING = 'PEM'


class GenerateKey:
    def __init__(self, bit_len, path):
        self.bit_len = bit_len
        self.path = path
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key()

    def generate_private_key(self):
        return RSA.generate(self.bit_len)

    def generate_public_key(self):
        return self.private_key.publickey()

    def save_private_key(self):
        with open(os.path.join(self.path, 'private_key.txt'), 'wb') as file:
            file.write(self.private_key.exportKey(FORMAT_ENCODING))

    def save_public_key(self):
        with open(os.path.join(self.path, 'public_key.txt'), 'wb') as file:
            file.write(self.public_key.exportKey(FORMAT_ENCODING))

    def get_private_key(self):
        with open(os.path.join(self.path, 'private_key.txt'), 'rb') as file:
            key = RSA.import_key(file.read())
        return key

    def get_public_key(self):
        with open(os.path.join(self.path, 'public_key.txt'), 'rb') as file:
            key = RSA.import_key(file.read())
        return key
