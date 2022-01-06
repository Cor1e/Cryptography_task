#CBC bitflipping attacks
import random
from random import randint
import os
import string
# The below file is given by OPEN SSL
!pip install pycrypto
from Crypto.Cipher import AES
from math import ceil
from binascii import unhexlify, b2a_base64, a2b_base64, hexlify
import chardet
from os.path import commonprefix

#Helper Functions
def pkcs7(message, blocksize):
    padlen = blocksize-len(message)%blocksize
    if(padlen == blocksize):
        padlen = 0
    pkcsmessage=bytes([padlen])*padlen
    return message+pkcsmessage

def random_byte_create(lenofbytes):
    randomnumber=[]
    for i in range(lenofbytes):
        randomnumber.append(random.randint(0,255))
    return bytes(randomnumber)

block_size=16
IV = random_byte_create(block_size)
Key_global=random_byte_create(16)

def cbc_enc_dec(message, encrypt=True):
    if encrypt:
        #Given
        prefix = b'comment1=cooking%20MCs;userdata='
        suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

        append_plain_text = (prefix + message + suffix).replace(b'=', b'"="').replace(b';', b'";"')
        cipher_object=AES.new(Key_global,AES.MODE_CBC,IV)
        return cipher_object.encrypt(pkcs7(append_plain_text, block_size))
    else:
        cipher_object=AES.new(Key_global,AES.MODE_CBC,IV)
        return cipher_object.decrypt(message)

def validate_cbc(text):
    text_decrypted = cbc_bitflipping(text, encrypt=False)
    if b';admin=true;' in text_decrypted:
        return True
    else:
        return False

def cbc_bitflipping_attack():
  # The idea is that the change in bit of cipher text it  will produce huge error in one block but will produce 
  # Change in only one bit in the next block. This is because the ouput in second block is simply xor of ciphertext of  first block
  # and xor of dec(cipher text of next block). Also we know that the xor will cause no confusion or difusion
    encrypted_strings = [cbc_enc_dec(b'A'*0)]
    # Number of blocks taken up by the prefix:
    prefix_block_size = len(commonprefix([cbc_enc_dec(b''),cbc_enc_dec(b'A')])) // block_size + 1
    min_addition = None
    for blocks in range(1, block_size):
        encrypted_strings.append(cbc_enc_dec(b'A'*blocks))
        length_common_prefix = len(commonprefix(encrypted_strings))
        if length_common_prefix == prefix_block_size*block_size:
            min_addition = blocks-1
            break
        encrypted_strings = [encrypted_strings[-1]]
    assert min_addition is not None
    encrypted = cbc_enc_dec(b'A'*min_addition + b'xadminxtruex')
    print("Decrypted Message:",cbc_enc_dec(encrypted,False))
    print("Encypted Message:",encrypted)
    previous_block = [p for p in encrypted[(prefix_block_size-1)*block_size: prefix_block_size*block_size]]
    previous_block[0] ^= ord(b'x') ^ ord(b';')
    previous_block[6] ^= ord(b'x') ^ ord(b'=')
    previous_block[11] ^= ord(b'x') ^ ord(b';')
    previous_block = bytes(previous_block)
    print("Previous Block Decypted:",cbc_enc_dec(previous_block,False))
    print("Previous Block Encypted:",previous_block)
    admin_string = encrypted[:(prefix_block_size-1)*block_size] + previous_block + encrypted[prefix_block_size*block_size:]
    print("After appending Admin String 'Decypted':",cbc_enc_dec(admin_string,False))
    print("After appending Admin String:",admin_string)
    print("Does the Admin String has admin keyword?")
    return validate_cbc(admin_string)

if __name__== "__main__":
    print(cbc_bitflipping_attack())

'''
Decrypted Message: b'comment1"="cooking%20MCs";"userdata"="AAAAAAAAAAxadminxtruex";"comment2"="%20like%20a%20pound%20of%20bacon\x06\x06\x06\x06\x06\x06'
Encypted Message: b'OI\x97\x1d\xb2\x97UU\xeb_"\xad\xb8q\xael\xb3\xd5G\x88\xf9\xd0>w\xd4\xe7\xb2\x11L\x00\xdc\xb5f&\xb9=!\xe4K\x13\x06\xfb\xfb(\x16\x05\xb9cdk\xa6\x99/\xbfY\'\x96\xac/\\\xdb\xab\x89\x8f\x1d\xf1E\xbbm\x89\xe7\x0c2\xba\xd6%\x87\xa7\x1dN\x07\xedD\x84\xf6\x01\xbae?t|\xb9 \x98\xca\xde\xb7b\x0f\xbe\r[*H\x8e\xe5\xd2?n\xbb%\xb0'
Previous Block Decypted: b'uQ\xca\xfe\xce\x80\xc8\x19\xd6\xe9\xf8\xea\xea\x95\xe3\xe5'
Previous Block Encypted: b'%&\xb9=!\xe4\x0e\x13\x06\xfb\xfbk\x16\x05\xb9c'
After appending Admin String 'Decypted': b'comment1"="cooking%20MCs";"userd\xe5\xc2\x1c=\xfd>\x9885\xf1r\xe8\x02\x83\xa9\x1e;admin=true;";"comment2"="%20like%20a%20pound%20of%20bacon\x06\x06\x06\x06\x06\x06'
After appending Admin String: b'OI\x97\x1d\xb2\x97UU\xeb_"\xad\xb8q\xael\xb3\xd5G\x88\xf9\xd0>w\xd4\xe7\xb2\x11L\x00\xdc\xb5%&\xb9=!\xe4\x0e\x13\x06\xfb\xfbk\x16\x05\xb9cdk\xa6\x99/\xbfY\'\x96\xac/\\\xdb\xab\x89\x8f\x1d\xf1E\xbbm\x89\xe7\x0c2\xba\xd6%\x87\xa7\x1dN\x07\xedD\x84\xf6\x01\xbae?t|\xb9 \x98\xca\xde\xb7b\x0f\xbe\r[*H\x8e\xe5\xd2?n\xbb%\xb0'
Does the Admin String has admin keyword?
True
'''