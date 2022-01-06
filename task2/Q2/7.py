#PKCS#7 padding validation
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

#Validate the padding
def PKCS_7_padding_validation(padded_message):
    #text=bytes(padded_message,'utf-8')
    #Last byte gives number of blocks padded
    last_byte=padded_message[-1]
    if last_byte>len(padded_message):
        return ValueError('Padding is Invalid')
    for x in range(last_byte,0,-1):
        if padded_message[-x]!=last_byte:
        # This simply goes last padded bytes before and checks
        return ValueError('Padding is Invalid')
    return padded_message[:-last_byte]

if __name__== "__main__":
    test_byte_string=b'ICE ICE BABY\x04\x04\x04\x04'
    print(PKCS_7_padding_validation(test_byte_string))
    test_byte_string=b'ICE ICE BABY\x05\x05\x05\x05'
    print(PKCS_7_padding_validation(test_byte_string))
    test_byte_string=b'ICE ICE BABY\x01\x02\x03\x04'
    print(PKCS_7_padding_validation(test_byte_string))

'''
b'ICE ICE BABY'
Padding is Invalid
Padding is Invalid
'''