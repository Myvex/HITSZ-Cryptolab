import random
import sys
import time

sys.setrecursionlimit(100000) #设置一个较大递归深度以保证程序运行
#构造字典
dic =  {'0': '00', '1': '01', '2': '02', '3': '03', '4': '04', '5': '05',
        '6': '06', '7': '07', '8': '08', '9': '09', 'a': '10', 'b': '11',
        'c': '12', 'd': '13', 'e': '14', 'f': '15', 'g': '16', 'h': '17',
        'i': '18', 'j': '19', 'k': '20', 'l': '21', 'm': '22', 'n': '23',
        'o': '24', 'p': '25', 'q': '26', 'r': '27', 's': '28', 't': '29',
        'u': '30', 'v': '31', 'w': '32', 'x': '33', 'y': '34', 'z': '35',
        'A': '36', 'B': '37', 'C': '38', 'D': '39', 'E': '40', 'F': '41',
        'G': '42', 'H': '43', 'I': '44', 'J': '45', 'K': '46', 'L': '47',
        'M': '48', 'N': '49', 'O': '50', 'P': '51', 'Q': '52', 'R': '53',
        'S': '54', 'T': '55', 'U': '56', 'V': '57', 'W': '58', 'X': '59',
        'Y': '60', 'Z': '61', ' ': '62', 'None': '63', ',': '64', '.': '65',
        '-': '66'}


#字符与数字之间的映射
def transferToNum(str):
    m = ""
    for d in str:
        m += dic[d]
    return m

def transferTostr(num):
    n = ""
    for i in range(0,len(num),2):
       n += {value:key for key,value in dic.items()}[num[i]+num[i+1]]
    return n

def get_e(phi):
    e = random.randint(2, phi-1)
    while(gcd(e, phi) != 1):
        e = e+1
    return e

# 快速幂算法求解a的b次方模c
def pow_mod(a, b, c):
    ans = 1
    a = a % c
    while b > 0:
        if b & 1 == 1:
            ans = (ans * a) % c
        b = b >> 1
        a = (a * a) % c
    return ans

# Miller-Rabin算法
# 返回True，很可能为素数
# 返回False，不是素数
def miller_rabin(n):
    if n == 2:
        return True
    elif n == 1 or n & 1 == 0:
        return False
    else:
        # 先找出正整数k和奇数q，使得2的k次方乘上q等于n-1
        k = 0
        q = n - 1
        while q & 1 == 0:
            k += 1
            q = q >> 1
        a = random.randint(2, n - 2)
        temp = pow_mod(a, q, n)
        if temp == 1 or temp == (n - 1):
            return True
        for j in range(1, k):
            if pow_mod(a, q * 2 ** j, n) == n - 1:
                return True
        return False


# 生成一个大数
# 所生成大数的二进制长度默认为1024bit
def generate_big_num(digit=1024):
    num = 0
    for i in range(digit):
        num = num * 2 + random.randint(0, 1)
    return num



def gcd(a,b): # 欧几里德算法
    if a<b:
        t=a
        a=b
        b=t
    while a%b!=0:
        temp=a%b
        a=b
        b=temp
    return b


def ext_gcd(a, b): # 扩展欧几里德算法
    if b == 0:
        x1 = 1
        y1 = 0
        x = x1
        y = y1
        r = a
        return r, x, y
    else:
        r, x1, y1 = ext_gcd(b, a % b)
        x = y1
        y = x1 - a // b * y1
        return r, x, y



# 生成公钥私钥，p、q为两个超大质数
def gen_key(p, q):
    n = p * q
    fn = (p - 1) * (q - 1)      # 计算与n互质的整数个数 欧拉函数
    e = get_e(fn)
    # e = 65537
    print("n =",n)
    print("e =",e)
    print("fn =",fn)

    a = e
    b = fn
    
    x = ext_gcd(a, b)[1]
    

    if x < 0:
        d = x + fn
    else:
        d = x
    print("d=",d)
    #print("公钥:"+"("+str(n)+","+str(e)+")\n私钥:"+"("+str(n)+","+str(d)+")")
    return (e, n), (d, n)
    
# 加密 m:str是被加密的信息 加密成为c:str
def encrypt(m, pubkey):
    start_time = time.time()  # 记录加密开始时间
    e = pubkey[0]
    n = pubkey[1]
    c = ''
    std_c_part_len = 0
    g_num = len(m) // 4
    rest = len(m) % 4
    for i in range (0, g_num):
        m_part = int(m[i*4: i*4+4])
        c_part = str(pow_mod(m_part, e, n))# 计算 m^e % n
        c_part_len = len(c_part)
        if(i == 0):
            std_c_part_len = c_part_len + 8
        numof0 = std_c_part_len - c_part_len

        if(numof0 != 0):
            c_part = '0'*numof0 + c_part
        
        c += c_part
    if(rest != 0):
        m_part = int(m[g_num*4: g_num*4+2] + '63')
        
        c_part = str(pow_mod(m_part, e, n))
        
        c_part_len = len(c_part)
        numof0 = std_c_part_len - c_part_len
        if(numof0 != 0):
            c_part = '0'*numof0 + c_part
        
        c += c_part

    end_time = time.time()  # 记录加密结束时间
    encrypt_duration = end_time - start_time  # 计算加密时长
    print("加密持续时间是：", encrypt_duration, "秒")  # 输出加密时长
    
    return c, std_c_part_len

# 解密 c:str是密文，解密为明文m:str
def decrypt(c, selfkey, c_part_len):

    start_time = time.time()  # 记录解密开始时间

    d = selfkey[0]
    n = selfkey[1]
    m = ''
    g_num = len(c) // c_part_len

    for i in range(0, g_num):
        c_part = int(c[i*c_part_len: i*c_part_len+c_part_len])
        m_part = str(pow_mod(c_part, d, n))
        if(len(m_part) != 4):
            m_part = (4-len(m_part))*'0' + m_part
        
        m += m_part
    
    
    if(m[len(m)-2: len(m)] == '63'):
        m = m[0: len(m)-2]

    end_time = time.time()  # 记录解密结束时间
    decrypt_duration = end_time - start_time  # 计算解密时长
    print("解密持续时间是：", decrypt_duration, "秒")  # 输出解密时长
    
    return m
    
    
if __name__ == "__main__":

    p = generate_big_num()
    while not miller_rabin(p):
        p += 1
    print("使用Miller-Rabin算法生成一个二进制位数为1024bit的大素数p:")
    print("p =", p)

    q = generate_big_num()
    while not miller_rabin(q):
        q += 1
    print("使用Miller-Rabin算法生成一个二进制位数为1024bit的大素数q:")
    print("q =", q)


    print("2.生成公钥和私钥")
    pubkey, selfkey = gen_key(p, q)

    print("3.读取明文(lab2-Plaintext.txt)")
    with open("lab2-Plaintext.txt", "r", encoding='utf-8') as f:
        plaintext = f.read()
    print(plaintext)

    f.close()
    m = transferToNum(plaintext)

    print("4.用公钥加密信息")
    c, c_part_len = encrypt(m, pubkey)
    #print("密文:",transferTostr(c))
    with open("encrypted-text.txt", "w", encoding="utf-8") as fout1:
        fout1.write(c)
        fout1.close()
    print("该密文已被写入到文件encrypted-text.txt中")

 
    print("5.用私钥解密")
    d = decrypt(c, selfkey, c_part_len)
    print("明文:",transferTostr(d))
    with open("decrypted-text.txt", "w", encoding="utf-8") as fout2:
        fout2.write(transferTostr(d))
        fout2.close()
    print("该明文已经被同时写入到文件decrypted-text.txt中")



