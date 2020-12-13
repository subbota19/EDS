from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from log import Logging
from gen_key import GenerateKey

BIT_LEN = 2048
PATH = "/home/logic/tmp"
ENCODING = "utf-8"
logger = Logging(name=__name__).get_logger()


class EDS:
    def __init__(self, text=None):
        self.gen_key = GenerateKey(bit_len=BIT_LEN, path=PATH)
        self.signature = None
        self.text = text

    @staticmethod
    def get_hash_sha_512(bin_text):
        return SHA512.new(bin_text)

    def encrypt(self):
        logger.info('...encrypt...')
        logger.info("generating keys is started...")
        self.gen_key.save_private_key()
        self.gen_key.save_public_key()

        logger.info(
            'general info:\npath to keys - {};\nbit_len - {};\ne - {}\nn - {}\np - {}\nq - {}'.format(
                PATH, BIT_LEN, self.gen_key.get_public_key().e, self.gen_key.get_public_key().n,
                self.gen_key.get_private_key().p, self.gen_key.get_private_key().q)
        )
        private_key = self.gen_key.get_private_key()

        gen_hash = self.get_hash_sha_512(self.text.encode(ENCODING))

        logger.info(
            'hash info:\nhash digest representation - {}\nhash in 16-format - {}'.format(
                gen_hash.oid, gen_hash.hexdigest()))

        self.signature = pkcs1_15.new(private_key).sign(gen_hash)

        logger.info('signature - {}'.format(self.signature))

    def decrypt(self):
        logger.info('...decrypt...')
        is_valid_signature = False
        public_key = self.gen_key.get_public_key()

        gen_hash = self.get_hash_sha_512(self.text.encode(ENCODING))

        logger.info(
            'hash info:\nhash digest representation - {}\nhash in 16-format - {}'.format(
                gen_hash.oid, gen_hash.hexdigest()))
        try:
            pkcs1_15.new(public_key).verify(gen_hash, self.signature)
            print("The signature is valid")
            is_valid_signature = True
        except (ValueError, TypeError):
            print('The signature is not valid')
        logger.info('Result: is valid signature - {}'.format(is_valid_signature))
