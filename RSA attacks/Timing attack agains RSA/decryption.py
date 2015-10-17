#!/usr/bin/python
import math
base = 2**64-1
def getOmega(n):
    t=1;
    n0 = n % (2**64)
    for i in range(1,64):
        t=t*t*n0 % (2**64)
    t = 2**64-t
    return t

def getRho2(n):
    ln = int(math.ceil(math.log(n,2**64)))
    t=1;
    for i in range(1,2*ln*64+1):
        t =t*2;
        t = t % n
    return t
  
def ceil_div(n,d):
    return (n+d-1)/d
  
def bits(x):
    return math.frexp(x)[1]

def limbs(x):
    return ceil_div(bits(x),64)
   
def hammingWeight(x):
    return bin(x).count("1")

def montMulRed(x,y,n,omega):
    red = 0
    r=0;
    x0 = x & base
    for i in range (0,limbs(n)):
        yi = y&base
        y >>= 64
        r0 = r & base
        u = ((r0+yi*x0)*omega) & base
        uN = u*n
        yix = x*yi
        r+=yix+uN
        r  >>= 64
    if r>=n:
        #print "wtf"
        red = 1
        r -= n
    return r, red
    
def montMul(x,y,n,omega):
    r=0;
    x0 = x & base
    for i in range (0,limbs(n)):
        yi = y&base
        y >>= 64
        r0 = r & base
        u = ((r0+yi*x0)*omega) & base
        uN = u*n
        yix = x*yi
        r+=yix+uN
        r  >>= 64
    if r>=n:
        r -= n
    return r
    
def l2rExp(x,y,n):
    
    rho2 = getRho2(n)
    omega = getOmega(n)
    x = montMul(x,rho2,n,omega)
    t = montMul(1,rho2,n,omega)
    for i in reversed(range(0,bits(y))):
        t = montMul(t,t,n,omega)
        if (y>>i& 1) == 1:
            t = montMul(t,x,n,omega)
    t = montMul(t,1,n,omega)
    return t
        
    
    
    
if __name__ == "__main__"    :
    import sys
    inputBase = 10
    if len(sys.argv) > 1:
        if sys.argv[1]=="-hex":
            inputBase = 16
    
    c = int(raw_input(),inputBase)
    n = int(raw_input(),inputBase)
    d = int(raw_input(),inputBase)
    
    print l2rExp(c,d,n)
    
        
    
    
