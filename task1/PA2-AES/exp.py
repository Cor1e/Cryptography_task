from pwn import *
import threading
import struct
from random import randrange, randint
import copy
import sys
import time

BLOCK_SIZE = 16
BLOCK_NUM = 3
MAX_THREAD_NUM = int(sys.argv[1]) if len(sys.argv) >= 2 else 1


ciphertext = "9F0B13944841A832B2421B9EAF6D9836813EC9D944A5C8347A7CA69AA34D8DC0DF70E343C4000A2AE35874CE75E64C31"
ctext = [(int(ciphertext[i:i+2], 16)) for i in range(0, len(ciphertext), 2)]

p = remote("128.8.130.16", 49101)
#context.log_level = "debug"

BLOCKS = [ctext[0:BLOCK_SIZE], ctext[BLOCK_SIZE:BLOCK_SIZE*2],
          ctext[BLOCK_SIZE*2:BLOCK_SIZE*3]]
INIT_IV = BLOCKS[0]


def do_pack_send(ctext, num_blocks):
    p.sendline(struct.pack("<B", num_blocks)+bytes(ctext)+struct.pack("<B", 0))
    res = p.recv(2)
    return True if res == b"1\x00" else False


def guess_block3_padding_size():
    for i in range(0, BLOCK_SIZE+1):
        p_size = i
        B = copy.deepcopy(BLOCKS)
        raw_b = B[1][-i-1]
        rand_b = randint(1, 255)
        B[1][-i-1] = raw_b+1 if rand_b == raw_b else rand_b
        payload = B[0]+B[1]+B[2]
        if do_pack_send(payload, 3):
            print(f"block3 padding size:", p_size)
            break
    return p_size


def do_cracking(p_size):
    plain_text = [[-1 for y in range(BLOCK_SIZE)] for x in range(BLOCK_NUM-1)] + [
        [-1 if _ < BLOCK_SIZE-p_size else p_size for _ in range(BLOCK_SIZE)]]
    print("Initial plain_text:", plain_text)

    for bi in range(BLOCK_NUM-1, 0, -1):
        B = copy.deepcopy(BLOCKS)
        _start = p_size+1 if bi == BLOCK_NUM-1 else 1
        for ps in range(_start, BLOCK_SIZE+1):
            tmp_B = copy.deepcopy(BLOCKS)
            print(tmp_B)

            # re padding
            for i in range(ps-1):
                # A' = A ^ C ^ C'
                vuln_byte = (plain_text[bi][-i-1] ^
                             tmp_B[bi-1][-i-1] ^ ps) & 0xff
                tmp_B[bi-1][-i-1] = vuln_byte
            print(tmp_B)

            # Forged bytes
            _success = False
            for _ch in range(256):
                tmp_B[bi-1][-ps] = _ch
                payload = []
                for i in range(bi+1):
                    payload += tmp_B[i]
                print(f"Cracking block{bi+1}[{BLOCK_SIZE-ps}]:", tmp_B)
                if do_pack_send(payload, bi+1):
                    plain_text[bi][-ps] = (ps ^ _ch ^ B[bi-1][-ps]) & 0xff
                    print(f"Refreshed plain_text[{bi}]:", plain_text[bi])
                    _success = True
            if not _success:
                print("ERROR!")
                sys.exit(-1)

    return plain_text


plain_text = do_cracking(guess_block3_padding_size())
challenge_msg = b""
for i in range(1, BLOCK_NUM):
    challenge_msg += bytes(plain_text[i])
print("plain_text:", plain_text)
print("Challenge message:", challenge_msg)

p.close()
