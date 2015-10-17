#!/usr/bin/python
import subprocess, math, hashlib, binascii
threshold_brute = 5 #depending on the machine, this limit can be increased up to 15-20
queryNo = 0
line = "==============================\n"
def oracle(att):
    global queryNo
    queryNo+=1
    #exe = subprocess.Popen(exe_name,
    #                   stdout = subprocess.PIPE,
    #                   stdin = subprocess.PIPE)
    exe_in.write("{0:0256X}\n".format(att))
    response = int(exe_out.readline().strip())
    if response!=1 and response!=2:
        print "Something might have gone wrong"
    return response

# In the 3rd stage of the attack when log_2(max-min) < threshold_brute
# I stop calling the oracle and brute force the interval; this saves a few 
# oracle calls (up to 15-20) but is quite slow
def brute(n,e,c,min,max):
    for i in range (min,max+1):
        if c==pow(i,e,n):
            return i
    return -1
    

def main(n,e,c):
    b = 2**1016
    #step 1
    print line+"STEP 1"
    f1=1
    while True :
        f1 = f1 * 2
        att = c * pow(f1,e,n) % n
        response = oracle(att)
        if response == 1: # >=B
            break
    f1=f1/2
    print "total oracle calls: "+str(queryNo)
    
    #step 2
    print line+"STEP 2"
    f2 = ((n+b) / b * f1) % n
    while True:
        att = (pow(f2,e,n) * c) % n
        response = oracle(att)
        if response != 1: # <B
            break
        f2 = (f2 + f1) % n
    print "total oracle calls: "+str(queryNo)
    
    #step 3
    print line+"STEP 3\n(this will take a while)"
    min = (n + f2 - 1) / f2
    max = (n + b) / f2
    log_diff = int(math.log(max-min,2))
    while  log_diff> threshold_brute:
        log_diff = int(math.log(max-min,2))
        print log_diff
        f_tmp = 2 * b / (max-min)
        i = f_tmp * min / n
        f3 = (i*n + min -1)/min
        att = pow(f3,e,n) * c % n
        response = oracle(att)
        if response == 1: #>=B
            min = (i*n+b+f3-1)/f3
        else:
            max = (i*n+b) / f3
        log_diff = int(math.log(max-min,2))
    # brute force the message
    print "Switch to brute force"
    message = brute(n,e,c,min,max)
    
    if message==-1:
        print "Something went wrong. The recovered padded message is not correct"
        print "{0:0256X}".format(message)
        print queryNo
    
    message = "{0:0256X}".format(message)
    print line+"Message recovered after the attack:"
    print message
    
    print line+"Decoding the message"
    decryption(message)

   
def I2OSP(x, xLen):
    if x> 256**xLen:
        raise Exception("xLen is too big in I2OSP")
    h = hex(x)
    h=h[2:]
    if h[-1]=='L':
        h=h[:-1]
    if len(h) % 2 :
        h = '0%s'%h
    
    x=h.decode('hex')
    return "\x00" * (xLen-len(x))+x
 
def MGF(mgfSeed, maskLen,hLen=-1):
    if maskLen > 2**32:
        raise Exception ("mask too long in MFG1")
        
    if hLen == -1:
        hLen = hashlib.sha1("").digest_size
    
    T=""
    for i in range (0,(maskLen+hLen-1)/hLen):
        c = I2OSP(i,4)
        T = T + hashlib.sha1(mgfSeed+c).digest()
    return T[:maskLen]
  
def stringXOR(a,b):
    r=""
    for i in range (0, min(len(a),len(b))):
        r+=chr(ord(a[i])^ord(b[i]))
    return r
  
  
def decryption(message, k=256):
    
    message = message.decode('hex') #convert message to byte string
    
    lHash = hashlib.sha1("")
    hLen = lHash.digest_size
    lHash = lHash.digest()
    
    Y          = message[0]
    maskedSeed = message[1:1+hLen]                                           # Separate DB into an octet string lHash' of length hLen, a 
    maskedDB   = message[1+hLen:]                                            # (possibly empty) padding string PS consisting of octets with
    if (Y != "00".decode('hex')):                                            # hexadecimal value 0x00, and a message M as
        raise Exception ('Recovered message does not start with "00"');      #
    seedMask = MGF(maskedDB, hLen)                                           #    DB = lHash' || PS || 0x01 || M.
    seed = stringXOR(maskedSeed,seedMask)                                    #
    dbMask = MGF(seed,k-hLen-1)                                              # If there is no octet with hexadecimal value 0x01 to separate PS
                                                                             # from M, if lHash does not equal lHash', or if Y is non-zero,
    DB = stringXOR(maskedDB, dbMask)                                         # output "decryption error" and stop.  (See the note below.)
    lHash1 = DB[:hLen]
    right = DB[hLen:]
    
    
    
    if lHash != lHash1:
        raise Exception('Different hash labels')
    pos = right.find(chr(1))
    
    if pos == -1:
        raise Exception('No 0x01 octet')
    
    m = right[pos+1:]
    print line
    print "message(ASCII):"
    print m
    
    print "message(hex) and number of queries:"
    print m.encode('hex')
    print queryNo

if __name__ == "__main__":
    import sys
    # message = "00643359D50BB78430B944CEC195CF58D1A3B6534CEA99974A0E68A5D20F92038AFD85DB098B3DA8BFFC622E1B9BE91AE8BBFEFB40AA19001CCEFDEA13B30D637D592EDD580371D57826C0475E8EC0D2AE218C294CAFD2351F40EBB3C73FD40C86D6201577AACA3000CF58C59E9913C9921FBE8E5A56EF34A51285FB4ECE26B5"
    # MGF(message[0:2],10)
    # decryption(message)
    
    if len(sys.argv)!=3:
        raise Exception("Incorrect number of arguments")
    exe_name = "./"+sys.argv[1]
    exe = subprocess.Popen(exe_name, 
                        stdout = subprocess.PIPE,
                        stdin = subprocess.PIPE)
    exe_in  = exe.stdin
    exe_out = exe.stdout
    params_file = open(sys.argv[2])
    n = int(params_file.readline(),16)
    e = int(params_file.readline(),16)
    c = int(params_file.readline(),16)
    params_file.close()
    main(n,e,c)






    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    