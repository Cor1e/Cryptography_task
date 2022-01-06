#!/usr/bin/python3

import base64
import binascii
import re
import os
import random
from random import randint
import math
from itertools import zip_longest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

import IPython.display

_HTML_INFO_STYLE = ( 'border:1px solid #c3e6cb;'
   'padding:.75rem 3rem;'
   'border-radius:.5rem;'
   'font-weight:bold;'
   'text-align: center;'
)

def html_test(condition):
    if condition:
        html = IPython.display.HTML(
            '<div style="' +
            _HTML_INFO_STYLE +
            'background-color:#d4edda;'
            'color:#155724;'
            'border-color:#c3e6cb;'
            '">OK</div>')
    else:
        html = IPython.display.HTML(
            '<div style="' +
            _HTML_INFO_STYLE +
            'background-color:#f8d7da;'
            'color:#721c24;'
            'border-color:#f5c6cb;'
            '">ERROR</div>')

    IPython.display.display(html)
    

# block size seems to be 16 bytes (128 bits) all along the challenges
BLOCK_SIZE = 16

def bxor(a, b, longest=True):
    if longest:
        return bytes([ x^y for (x, y) in zip_longest(a, b, fillvalue=0)])
    else:
        return bytes([ x^y for (x, y) in zip(a, b)])

from math import ceil
def split_bytes_in_blocks(x, blocksize):
    nb_blocks = ceil(len(x)/blocksize)
    return [x[blocksize*i:blocksize*(i+1)] for i in range(nb_blocks)]
    
# Challenge 8 and Challenge 11
def test_ecb_128(ctxt):
    """test wether ctxt is a ECB mode ciphertext"""
    num_blocks = len(ctxt)//16
    return len(set([ctxt[i*16:(i+1)*16] for i in range(num_blocks)])) < num_blocks

# PKCS#7 padding

class PaddingError(Exception):
    pass

def pkcs7_padding(message, block_size):
    padding_length = block_size - ( len(message) % block_size )
    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length]) * padding_length
    return message + padding

def pkcs7_strip(x, block_size):
    if not len(x) % block_size == 0:
        raise PaddingError
        
    last_byte = x[-1]
    
    # the 'int' is superfluous here
    # as last_byte is already an int (for Python a byte string is a list of integers)
    # but this way it's clearer what we are doing
    padding_size = int(last_byte)

    if padding_size > block_size:
        raise PaddingError('illegal last byte (greater than block size)')
    if padding_size == 0:
        raise PaddingError('illegal last byte (zero)')
    
    if not x.endswith(bytes([last_byte])*padding_size):
        raise PaddingError

    return x[:-padding_size]

# AES one-block

def encrypt_aes_128_block(msg, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(msg) + encryptor.finalize()

def decrypt_aes_128_block(ctxt, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
    return decrypted_data

# AES ECB (with padding)

def encrypt_aes_128_ecb(msg, key):
    block_size = 16
    padded_msg = pkcs7_padding(msg, block_size)
    return b''.join([
        encrypt_aes_128_block(block, key)
        for block in split_bytes_in_blocks(padded_msg, block_size)
    ])

def decrypt_aes_128_ecb(ctxt, key):
    block_size = 16
    padded_msg = b''.join([
        decrypt_aes_128_block(block, key)
        for block in split_bytes_in_blocks(ctxt, block_size)
    ])
    return pkcs7_strip(padded_msg, block_size)

for _ in range(4):
    key = os.urandom(16)
    msg = os.urandom(randint(8,18))
    ctxt = encrypt_aes_128_ecb(msg, key)
    assert decrypt_aes_128_ecb(ctxt, key) == msg

# AES CTR (no padding required)

def aes_128_ctr_keystream_generator(key, nonce):
    counter = 0
    while True:
        to_encrypt = (nonce.to_bytes(length=8, byteorder='little')
                     +counter.to_bytes(length=8, byteorder='little'))
        keystream_block = encrypt_aes_128_block(to_encrypt, key)
        # equivalent to "for byte in keystream_block: yield byte"
        # for the "yield" keyword in Python,
        # see https://docs.python.org/3/tutorial/classes.html#generators
        yield from keystream_block

        counter += 1

def transform_aes_128_ctr(msg, key, nonce):
    '''does both encryption (msg is plaintext)
    and decryption (msg is ciphertext)'''

    keystream = aes_128_ctr_keystream_generator(key, nonce)
    return bxor(msg, keystream, longest=False)

# AES CBC (with padding)

def encrypt_aes_128_cbc(msg, iv, key):
    block_size = 16
    padded_msg = pkcs7_padding(msg, block_size)
    result = b''
    mask = iv
    for block in split_bytes_in_blocks(padded_msg, block_size):
        tmp = bxor(block, mask)
        enc_block = encrypt_aes_128_block(tmp, key)
        # in CBC, each block of ciphertext
        # is used as a XOR mask on the next block of plaintext
        mask = enc_block
        result += enc_block
    return result

def decrypt_aes_128_cbc(ctxt, iv, key):
    block_size = 16
    padded_msg = b''
    mask = iv
    for enc_block in split_bytes_in_blocks(ctxt, block_size):
        tmp = decrypt_aes_128_block(enc_block, key)
        padded_msg += bxor(mask, tmp)
        mask = enc_block
    return pkcs7_strip(padded_msg, block_size)

for _ in range(4):
    key = os.urandom(16)
    iv = os.urandom(16)
    msg = os.urandom(randint(8,48))
    ctxt = encrypt_aes_128_cbc(msg, iv, key)
    assert decrypt_aes_128_cbc(ctxt, iv, key) == msg


# bit flipping on CBC ciphertexts

def cbc_xor(cryptogram, pad, index):
    ctxt = cryptogram['ctxt']
    iv = cryptogram['iv']

    if len(pad) > BLOCK_SIZE - (index % BLOCK_SIZE):
        raise ValueError('pad cannot cover several blocks')

    if isinstance(index, tuple):
        # allowing negative block number and in-block index
        block_nb = index[0] % (len(ctxt) // BLOCK_SIZE)
        index_in_block = index[1] % (BLOCK_SIZE)

        index = block_nb*BLOCK_SIZE + index_in_block
    else:
        # allowing negative bit index
        index = index % len(ctxt)

    if index < BLOCK_SIZE:
        iv = bxor(iv, (b'\x00'*index) + pad)
    else:
        ctxt = bxor(ctxt, b'\x00'*(index-BLOCK_SIZE) + pad)

    return {'ctxt': ctxt, 'iv':iv}

# TODO move to a test script
# we don't want to run this at every import
for _ in range(20):
    msg_length = randint(
            BLOCK_SIZE+1, # bit flipping on short messages not implemented
            4*BLOCK_SIZE)
    msg = os.urandom(msg_length)
    key = os.urandom(16)
    iv = os.urandom(16)
    ctxt = encrypt_aes_128_cbc(msg, key, iv)
    cryptogram = {'ctxt': ctxt, 'iv': iv}

    pad_beginning = randint(BLOCK_SIZE, msg_length-1)
    # pad must not overflow on next block
    # (not doable with CBC bit flipping)
    max_pad_length = min(msg_length-pad_beginning,
                         BLOCK_SIZE - (pad_beginning % BLOCK_SIZE))
    pad_length = randint(1, max_pad_length)
    pad = os.urandom(pad_length)

    altered_cryptogram = cbc_xor(cryptogram, pad, pad_beginning)
    result = decrypt_aes_128_cbc(altered_cryptogram['ctxt'], key,
                                 altered_cryptogram['iv'])
    expected = bxor(msg, b'\x00'*pad_beginning + pad)

    # bit flipping will completely mess up one block of plaintext
    # so we don't want to compare that
    messed_up_block = (pad_beginning-BLOCK_SIZE) // BLOCK_SIZE
    before_mess = slice(0, BLOCK_SIZE*messed_up_block)
    after_mess = slice(BLOCK_SIZE*(messed_up_block+1), None)

    assert result[before_mess] == expected[before_mess]
    assert result[after_mess] == expected[after_mess]

def MT19937_32(seed=5489, state=None):
    '''Mersenne-Twister PRNG, 32-bit version'''
    # parameters for MT19937-32
    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF)
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    l = 18
    f = 1812433253

    # masks (to apply with an '&' operator)
    # ---------------------------------------
    # zeroes out all bits except "the w-r highest bits"
    # (i.e. with our parameters the single highest bit, since w-r=1)
    high_mask = ((1<<w) - 1) - ((1<<r) - 1)
    # zeroes out all bits excepts "the r lowest bits"
    low_mask = (1<<r)-1

    def twist(x):
        return (x >> 1)^a if (x % 2 == 1) else x >> 1

    if state == None:
        # initialization (populating the state)
        state = list()
        state.append(seed)
        for i in range(1, n):
            prev = state[-1]
            # the "& d" is to take only the lowest 32 bits of the result
            x = (f * (prev ^ (prev >> (w-2))) + i) & d
            state.append(x)

    while True:
        x = state[m] ^ twist((state[0] & high_mask) + (state[1] & low_mask))

        # tempering transform and output
        y = x ^ ((x >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        yield y ^ (y >> l)

        # note that it's the 'x' value
        # that we insert in the state
        state.pop(0)
        state.append(x)

def sha1(msg, state=None):
    # following RFC 3174
    # https://tools.ietf.org/html/rfc3174

    # we are prioritizing readability and similarity with the specs
    # over optimization

    # we are always in big-endian form in SHA1
    # (Section 2.c: "The least significant four bits of the integer are
    # represented by the right-most hex digit of the word representation")

    # to use as a bit mask for reduction modulo 2^32
    MAX_WORD = 0xFFFFFFFF

    # Section 3: Operations on Words

    def S(X, n):
        'circular left shift (a.k.a "rotate left")'
        # don't forget reduction modulo 2^32 !
        # it is not explicitely written in the formula in the RFC
        # (it is in the prose below it though)
        return ((X << n) | (X >> (32-n))) & MAX_WORD

    # Section 4: Padding

    # we are limiting ourselves to messages being byte strings
    # even though specification mentions bit strings of any length
    assert isinstance(msg, bytes)

    # message length in bits
    msg_length = len(msg)*8

    # we must append a "1" bit.
    # since we are always working with bytes
    # the appended bit will always be at the beginning of the next byte

    # computing the number of "zeroes" to append
    # we need msg_length + 1 + m + 64 = 0 mod 512
    # thus m = -(msg_length + 1 + 64) mod 512
    m = -(msg_length + 1 + 64) % 512

    # m+1 will always be a multiple of 8 in our case
    padded_msg = (msg
                  + bytes([0b10000000])
                  + b'\x00'*(m//8)
                  + msg_length.to_bytes(8, byteorder='big')
                 )

    words = [int.from_bytes(w, byteorder='big')
             for w in split_bytes_in_blocks(padded_msg, 4)]

    # "The padded message will contain 16 * n words"
    n = len(words)/16
    assert n.is_integer()
    n = int(n)

    # "The padded message is regarded as a sequence of n blocks M(1), M(2), …"
    M = split_bytes_in_blocks(words, 16)

    # Section 5: Functions and Constants Used

    def f(t, B, C, D):
        if 0 <= t <= 19:
            return (B & C) | ((~B) & D)
        elif 20 <= t <= 39 or 60 <= t <= 79:
            return B ^ C ^ D
        elif 40 <= t <= 59:
            return (B & C) | (B & D) | (C & D)
        else:
            raise Exception('t must be between 0 and 79 inclusive')

    # this could be optimized, for instance with an array
    # but this way is closer to how it is described in the specs
    def K(t):
        if 0 <= t <= 19:
            return 0x5A827999
        elif 20 <= t <= 39:
            return 0x6ED9EBA1
        elif 40 <= t <= 59:
            return 0x8F1BBCDC
        elif 60 <= t <= 79:
            return 0xCA62C1D6
        else:
            raise Exception('t must be between 0 and 79 inclusive')

    # Section 6: Computing the Message Digest
    # Using "method 1" (Section 6.1)

    # used for SHA-1 cloning
    if state == None:
        H0 = 0x67452301
        H1 = 0xEFCDAB89
        H2 = 0x98BADCFE
        H3 = 0x10325476
        H4 = 0xC3D2E1F0
    else:
        assert isinstance(state, tuple)
        assert len(state) == 5
        assert all(isinstance(x, int) for x in state)

        H0, H1, H2, H3, H4 = state

    for i in range(len(M)):
        W = M[i]
        assert len(W) == 16
        
        for t in range(16, 80):
            W.append( S(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16],
                        n=1) )

        A, B, C, D, E = H0, H1, H2, H3, H4

        for t in range(80):
            TEMP = (S(A, 5) + f(t, B, C, D) + E + W[t] + K(t)) & MAX_WORD

            E = D; D = C; C = S(B, 30); B = A; A = TEMP

        H0 = (H0 + A) & MAX_WORD
        H1 = (H1 + B) & MAX_WORD
        H2 = (H2 + C) & MAX_WORD
        H3 = (H3 + D) & MAX_WORD
        H4 = (H4 + E) & MAX_WORD

    result = b''.join(H.to_bytes(4, byteorder='big') for H in [H0, H1, H2, H3, H4])

    return result

# attacks
# =============

# bytes representing lowercase english letters and space
ascii_text_chars = list(range(97, 122)) + [32]

# from challenge 3
def attack_single_byte_xor(ciphertext):
    # a variable to keep track of the best candidate so far
    best = None
    for i in range(2**8): # for every possible key
        # converting the key from a number to a byte
        candidate_key = i.to_bytes(1, byteorder='big')
        keystream = candidate_key*len(ciphertext)
        candidate_message = bxor(ciphertext, keystream)
        nb_letters = sum([ x in ascii_text_chars for x in candidate_message])
        # if the obtained message has more letters than any other candidate before
        if best == None or nb_letters > best['nb_letters']:
            # store the current key and message as our best candidate so far
            best = {"message": candidate_message, 'nb_letters': nb_letters, 'key': candidate_key}
    return best
