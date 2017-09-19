import hashlib
import click

from hashlib import md5
from hashlib import sha256


# class Cipher(object):
#     pass

class hashSHA256():
    def encrypt(self, input_file, outfile):
        message = hashlib.sha256()
        file = input_file
        infile = open(file, 'r')

        out = open(outfile, 'w')

        for line in infile:
            line = line.encode('utf-8')
            message.update(line)
        out.write(str(message.hexdigest()))
        out.write("\n")

    def __init__(self): pass


class hashMD5():
    def encrypt(selfself, inputfile, outfile):
        message = hashlib.md5()
        file = inputfile
        infile = open(file, 'r')

        out = open(outfile, 'w')

        for line in infile:
            line = line.encode('utf-8')
            message.update(line)
        out.write(str(message.hexdigest()))
        out.write("\n")

    def __init__(self): pass


# ------------------------------------------------------------------------------------
cipher_list = (md5, sha256)
cipher_name_list = [Cipher.__name__.lower() for Cipher in cipher_list]
cipher_dict = {Cipher.__name__.lower(): Cipher for Cipher in cipher_list}


# collect all the distribution routines
# dist_dict = {'md5': hashMD5, 'sha256': hashSHA256}
# dist_name_list = [key for key in dist_dict]

# -------------------------------------------------------------------------------------

@click.group(context_settings=dict(help_option_names=['h', '--help']))
@click.pass_context
def cli(ctx):
    """
    :param ctx: A tool to encrypt to decrypt with sha256 or md5
    :return:
    """
    pass


@click.command()
@click.option('--cipher', '-c', 'cipher_name', type=click.Choice(cipher_name_list))
@click.argument('inputFile', type=click.File('rb'))
@click.argument('outputFile', type=click.File('wb'))
def encrypt(cipher_name, inputFile, outputFile):
    """ Encrypt a file using hashlib of choice:
            crypt[OPTIONS] encrypt <in_file> <out_file>
    """
    Cipher = cipher_dict[cipher_name]
    # plain_text = inputFile.read()
    #
    # cipher_text = cipher.encrypt(plain_text)
