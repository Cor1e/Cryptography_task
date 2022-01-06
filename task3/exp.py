from Crypto.Util.number import getPrime , long_to_bytes,bytes_to_long
from gmpy2 import invert , powmod , is_prime , gcd , next_prime , iroot
from functools import reduce
n = []
e = []
c = []
m = {}
solved = []

def CRT(mi, ai):
    M = reduce(lambda x, y: x * y, mi)
    ai_ti_Mi = [a * (M // m) * invert(M // m, m) for (m, a) in zip(mi, ai)]
    return reduce(lambda x, y: x + y, ai_ti_Mi) % M
def small_e_boardcast_attack(nlist , e , clist):
    m = CRT(nlist , clist)
    tmp = iroot(m , e)
    if tmp[1] == 1:
        return tmp[0]
    else:
        return 0

def same_module_attack(N , e1 , e2 , c1 , c2):
    d1 = invert(e1 , e2)
    d2 = (d1 * e1 - 1) // e2
    true_c2 = invert(c2 , N)
    return (powmod(c1 , d1 , N) * powmod(true_c2 , d2 , N)) % N
def Pollard_p_1(N):
    a = 2
    f = a
    # precompute
    while 1:
        for n in range(1,200000):
            f = powmod(f, n, N)
            if is_prime(n):
                d = gcd(f-1, N)
                if 1 < d < N:
                    return d , N//d
                elif d >= N:
                    f = next_prime(a)
                    break
        else:
            break
def Williams_p_1(N):
    def myplus(a , b , difference):
        return (a * b - difference) % N
    def myAverange(high, low ,difference):
        return ((low + high) * invert(difference , N)) % N
    def mymul(num , vn):
        num_bin = bin(num)[2:]
        lenth = len(num_bin)
        two_list = [vn]
        for i in range(lenth):
            temp = two_list[-1]
            two_list.append(myplus(temp , temp , 2))
        two_list.reverse()
        low = two_list[1]
        high = two_list[0]
        for i in range(1 , len(num_bin)):
            temp = myAverange(high , low , two_list[i+1])
            if num_bin[i] == '1':
                low = temp
            else:
                high = temp
        return low
    i = 2
    v = 15
    while 1:
        v = mymul(i , v)
        temp = gcd(v-2 , N)
        if 1 < temp < N:
            return temp , N // temp
        elif temp == N:
            return 0
        else:
            i += 1 
        if i > 100000:
            return 0

def _GetPlain(c):
    tmp = hex(c)[2:]
    if tmp[:16] != '9876543210abcdef':
        return 0
    number = int(tmp[16:24],16)
    plain = long_to_bytes(int(tmp[-16:] , 16))
    m[number] = plain
    return 1
def GetPlain(p , q , e , c):
    phi = (p-1)*(q-1)
    d = invert(e , phi)
    m = powmod(c , d , p*q)
    return _GetPlain(m)

def detect1():
    for i in range(21):
        for j in range(21):
            if i != j and n[i] == n[j] and e[i] != e[j]:
                tmp = _GetPlain(same_module_attack(n[i] , e[i],e[j],c[i],c[j]))
                if tmp == 1:
                    solved.append(i)
                    solved.append(j)
def detect2():
    for i in range(21):
        for j in range(21):
            if i != j:
                if 1 < gcd(n[i] , n[j]) < n[i]:
                    p = gcd(n[i] , n[j])
                    q1 = n[i] // p
                    q2 = n[j] // p
                    tmp1 = GetPlain(p , q1 , e[i],c[i])
                    tmp2 = GetPlain(p , q2 , e[j],c[j])
                    if tmp1 ==1:
                        solved.append(i)
                    if tmp2 == 1:
                        solved.append(j)

def detect3():
    for i in range(21):
        if i not in solved:
            tmp = Pollard_p_1(n[i])
            if isinstance(tmp , tuple):
                p , q = tmp
                if GetPlain(p,q,e[i],c[i]):
                    solved.append(i)

def detect4():
    for i in range(21):
        if i not in solved:
            p_q = iroot(n[i] , 2)[0]
            for _ in range(20000):
                p_q += 1
                if iroot(p_q**2 - n[i],2)[1] == 1:
                    tmp = iroot(p_q**2 - n[i],2)[0]
                    p = (p_q + tmp)
                    q = (p_q - tmp)
                    if GetPlain(p , q , e[i] , c[i]):
                        solved.append(i)
                    
def detect5():
    e = 5
    num = [3,8,12,16,20]
    nlist = [n[i] for i in num]
    clist = [c[i] for i in num]
    m = small_e_boardcast_attack(nlist , e ,clist)
    if _GetPlain(m):
        for i in num:
            solved.append(i)
def detect6():
    for i in range(21):
        if i not in solved:
            tmp = Williams_p_1(n[i])
            if isinstance(tmp , tuple):
                p , q = tmp
                if GetPlain(p,q,e[i],c[i]):
                    solved.append(i)



name = ['./data/Frame' + str(i) for i in range(21)]
for i in range(21):
    f = open(name[i] , 'r')
    data = f.read()
    tn , te , tc = int(data[:256] , 16) , int(data[256:512] , 16) , int(data[512:] , 16)
    n.append(tn)
    e.append(te)
    c.append(tc)
nlist = []
clist = []
for i in range(21):
    if e[i] == 3:
        nlist.append(n[i])
        clist.append(c[i])

detect1()#same module
detect2()#gcd attack
detect3()#pollard p-1
detect4()#Fermat attack
detect5()#broadcast attack
#detect6()#william p+1


m[2] = b'amous sa'
m[3] = b'ying of '
m[4] = b'Albert E'
#coppersmith in e3.sage

plain = b''
print(m)
for i in range(21):
    if i in m :
        plain += m[i]
    else:
        plain += b' '*8
print(plain)