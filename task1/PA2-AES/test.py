from oracle import *
import sys
from random import randrange
 
data = "9F0B13944841A832B2421B9EAF6D9836813EC9D944A5C8347A7CA69AA34D8DC0DF70E343C4000A2AE35874CE75E64C31"
 
ctext = [(int(data[i:i+2],16)) for i in range(0, len(data), 2)]
C = [ctext[:16], ctext[16:32], ctext[-16:]]
P = [[0] * 16, [0] * 16, [0] * 16]
IV = [[0] * 16, [0] * 16, [0] * 16]
 
Oracle_Connect()
for bi in range(2):
    b = 2 - bi
    for k in range(16):
        if b == 2:
            C1 = [C[0][:], C[1][:], C[2][:]]
        if b == 1:
            C1 = [C[0][:], C[1][:]]
        pos = 15 - k
        for i in range(pos):            
            C1[b-1][i] = randrange(256)

        for i in range(pos + 1, 16):
            C1[b-1][i] = (k + 1) ^ IV[b][i]
                                         
        ii = -1
        for i in range(256):
            C1[b-1][pos] = i
            if b == 2:
                rc = Oracle_Send(C1[0][:] + C1[1][:] + C1[2][:], 3)
            if b == 1:
                rc = Oracle_Send(C1[0][:] + C1[1][:], 2)
            if rc == 1:
                ii = i
                break
        IV[b][pos] = ii ^ (k + 1)
        P[b][pos] = C[b-1][pos] ^ IV[b][pos]
Oracle_Disconnect()
print (P[1])
print (P[2])
print (map(lambda x: str(unichr(x)), P[1]))
print (map(lambda x: str(unichr(x)), P[2]))
 
a = ""
print (("the text is: %s") % a.join(text))