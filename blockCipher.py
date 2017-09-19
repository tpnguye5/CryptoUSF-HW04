#reference forkd

import pycrypto, click, hashlib, base64
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64decode
from base64 import b64decode

BLOCK_SIZE = 16 #anaylzing 16 bytes

padding = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE)* \
                        chr(BLOCK_SIZE-len(s)% BLOCK_SIZE)
unpadding = lambda  s:s [: -ord(s[len(s)-1:])]
class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf-8')).hexidisgest()
    def encrypt(self, raw):
        raw = padding(raw)

        iv = Random.new().read(AES.block_size)

        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]

        cipiher = AES.new(self.key, AES.MODE_CBC, iv)

        return unpadding(cipher.decrypt(enc[16:])).decode('utf-8')


@click.group()
@click.option("--cipher, help = "returns an encrypted file")
def cli(cipher):
    """Action:
    encrypt
        encrypts a give file
    decrypt
        decrypts a given file

    Uses a contemporary block cipher: AES"""


@click.command()
# @click.argument("block_cipher_type", type = click.STRING)
#tells what data type click should except
@click.argument('password', type = click.STRING)
@click.argument("input_file", type =click.File)
@click.argument("output_file", type = click.File)

def encrypt(password, input_file, output_file):
    file = open(input_file, 'r')
    out = open(output_file, 'w')
    for line in file:
        m = AESCipher(password).encrypt(str(line))
    out.write(m)
    out.close()

    # #read in file
    # file = input_file
    # infile = open(file, 'r')
    #
    # #add padding before encrypting a plaintext of X bytes
    # #encrypt with PKCS7
    # length = 16- (len(data) % 16)
    # data += bytes([length] * length)
    # for line in infile:
    #

@click.command()
# @click.argument("block_cipher_type", type = click.STRING)
# tells what data type click should except
@click.argument("input_file", type=click.STRING)
@click.argument("output_file", type=click.STRING)
def AES_decrypt(password, input_file, output_file):
    #after decrypting, remove from the back of the plaintext as many bytes from the padding
    file = open(input_file, 'r')
    out = open(output_file, 'w')
    for line in file:
        m = AESCipher.decrypt(str(line))
    out.write(m)
    out.close()
