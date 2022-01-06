import os
import random
from random import randint
import base64
from libmatasano import encrypt_aes_128_ecb

class Oracle:
    def __init__(self):
        self.key = os.urandom(16)
        self.prefix = os.urandom(randint(1,15))
        self.target = base64.b64decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            "YnkK"
        )
    
    def encrypt(self, message):
        return encrypt_aes_128_ecb(
            self.prefix + message + self.target,
            self.key
        )

oracle = Oracle()

# Finding the block size (again)

previous_length = len(oracle.encrypt(b''))
for i in range(20):
    length = len(oracle.encrypt(b'X'*i))
    if length != previous_length:
        # got it !
        block_size = length - previous_length
        # the following quantities will be useful later to compute target length
        # where "aligned" means a length that is a  multiple of the block size
        size_prefix_plus_target_aligned = previous_length
        min_known_ptxt_size_to_align = i
        break
else:
    raise Exception('did not detect any change in ciphertext length')
    
# just checking we got it right
assert block_size == 16

# Finding the prefix size

from libmatasano import split_bytes_in_blocks

# XXX not ideal as
# this may not work if the prefix is larger than one block
# (cannot be the case the way we wrote our oracle, but just saying)
previous_blocks = None
for i in range(1, block_size+1):
    blocks = split_bytes_in_blocks(oracle.encrypt(b'X'*i), block_size)
    if previous_blocks != None and blocks[0] == previous_blocks[0]:
        # we are in the situation where
        # prefix_size + padding_size - 1 = block_size
        prefix_size = block_size - i + 1
        break
    previous_blocks = blocks
else:
    raise Exception('did not detect constant ciphertext block')
    
# just checking we got it right
assert prefix_size == len(oracle.prefix)

# now that we have the prefix size we can compute the size of the target
target_size = size_prefix_plus_target_aligned - min_known_ptxt_size_to_align - prefix_size

assert target_size == len(oracle.target)

# More or less same thing as in challenge 12

know_target_bytes = b""
for _ in range(target_size):
    # r+p+k+1 = 0 mod B
    r = prefix_size
    k = len(know_target_bytes)
    padding_length = (-k-1-r) % block_size
    padding = b"X" * padding_length

    # target block plaintext contains only known characters except its last character
    target_block_number = (k+r) // block_size
    target_slice = slice(target_block_number*block_size, (target_block_number+1)*block_size)
    target_block = oracle.encrypt(padding)[target_slice]

    # trying every possibility for the last character
    for i in range(2**8):
        message = padding + know_target_bytes + bytes([i])
        block = oracle.encrypt(message)[target_slice]
        if block == target_block:
            know_target_bytes += bytes([i])
            break

print(know_target_bytes.decode())