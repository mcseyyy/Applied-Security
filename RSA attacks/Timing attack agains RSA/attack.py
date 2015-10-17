#!/usr/bin/python
import subprocess, math, hashlib, binascii, sys, random
from decryption import getRho2, getOmega, montMul, montMulRed, bits, hammingWeight
from collections import deque
errors = 0
sampleSize = 2500 # initial number of sample ciphers generated for the attack
n_length = 1024 # this value will be overridden when n is read from params file
threshold_difference_init  = 3
threshold_difference = 4
threshold_individual = 1.999
threshold_brute = 15
average_n = 4
history_len = 10
oracleCalls = 0
test_length = 6
initial_guess=[]

# Returns the decryption time for the given cipher 
def oracle(c):
    global oracleCalls
    oracleCalls+=1
    exe_in.write("{0:0256x}\n".format(c))
    time = int(exe_out.readline().strip())
    deceyphered_message = exe_out.readline()
    return time

# Returns the message corresponding to the given cipher
def decrypt(c):
    global oracleCalls
    oracleCalls+=1
    exe_in.write("{0:0256x}\n".format(c))
    time = exe_out.readline()
    decipher = int(exe_out.readline().strip(),16)
    return decipher
    
                    
# Function that tests if the guessed key is correct given a message and its
# corresponding cipher text
def testKey(k):
    # 'message' and 'cipher' are declared globally
    if message == pow(cipher,k,n):
        return True
    return False

# Increase the number of sample ciphers to sampleSize    
def resample (m,t,res,sampleSize):
    for i in range(0,len(m)):
        res[0][i] = deque([],history_len)
        res[1][i] = deque([],history_len)
        res[1][i].append(montMul(m[i],m[i],n,omega))
        res[0][i].append(0)
    for i in range(len(m),sampleSize):
        r = random.getrandbits(n_length)
        while r>=n:
            r = random.getrandbits(n_length)
        t.append(oracle(r))
        m.append(montMul(r,rho2,n,omega)) #convert the message in Mont form and add it to the list
        res[0].append(deque([],history_len))
        res[1].append(deque([],history_len))
        res[1][i].append(montMul(m[i],m[i],n,omega))
        res[0][i].append(0)
    return m,t,res
    
# Generates 'sampleSize' random ciphers (m) and calculates the corresponding 
# decryption time (times) and some partial result of the exponentiation (x)  
def getRandomMessages(sampleSize):
    messages = [] # save the sample ciphers in Mont form
    times = []    # time taken to decrypt the cipher
    res = [[],[]]    # temporary memory to save the partial result of the partial exponentiation
    for i in range (0,sampleSize):
        if i%1500==0:
            print i
        r = random.getrandbits(n_length)
        while r>=n:
            r = random.getrandbits(n_length)
        times.append(oracle(r))
        messages.append(montMul(r,rho2,n,omega)) #convert the message in Mont form and add it to the list
        res[0].append(deque([],history_len))
        res[1].append(deque([],history_len))
        res[1][i].append(montMul(messages[i],messages[i],n,omega))
        res[0][i].append(0)
        
    return messages,times,res
 
# Given a partial key (key_guess), its bit_lengh (B), hamming weight (H), and
# the required maxLength, the function brutoe forces the last bits of the key
def brute(key_guess,B,H,maxLength):
    bitsLeft = maxLength-B-H
    # Last bit needs to be a '1' which means that bitsLeft>=2
    if bitsLeft<2:
        return 0
    
    # if bits_left==2 => only a '1' can be appended to the key
    if bitsLeft == 2:
        temp_key = (key_guess<<1) | 1
        #print "{0:b}".format(temp_key)
        if testKey(temp_key):
            return temp_key
        return 0
    
    #try adding a '0' to the key
    temp_key = key_guess<<1
    B+=1
    result = brute(temp_key,B,H,maxLength)
    if result!=0:
        return result
    
    #try adding a '1' to the key
    temp_key |= 1
    H+=1
    result = brute(temp_key,B,H,maxLength)
    if result!=0:
        return result
    return 0

# returns avg(M3-M4), avg(M1-M2) and the partial results given a partial key
def classify(res,m,n,omega,lastBit):
    # Initialise the subsets to empty lists and the counters to 0
    # (for each subset)
    r0 = [0,0]
    c0 = [0,0]
    r1 = [0,0]
    c1 = [0,0]

    # Classify each message depending if there was a reduction or not
    for i in range(0,sampleSize):
        # assuming that the bit is 1
        #print lastBit
        #print i
        #print len(res[0][i])
        temp1 = montMul(res[lastBit][i][-1],m[i],n,omega) #multiplication
        
        temp1,red = montMulRed(temp1,temp1,n,omega)      #squaring
        r1[red]+=t[i]
        c1[red]+=1
        
        #assuming that the bit is 0
        temp0,red = montMulRed(res[lastBit][i][-1],res[lastBit][i][-1],n,omega) #squaring
        r0[red]+=t[i]
        c0[red]+=1
        
        res[1][i].append(temp1)
        res[0][i].append(temp0)
   
    # Calculate the difference between the average times when we assume that
    # last bit is 0 and when the last bit is 1
    u0 = abs(float(r0[1])/c0[1] - float(r0[0])/c0[0])
    u1 = abs(float(r1[1])/c1[1] - float(r1[0])/c1[0])
    return u0,u1,res

# After correcting a bit in the key this function is called to check if the
# correction is right; I run the attack for test_length bits and check if the
# deviation between the 2 differences keeps being above a threshold
def test_errorFix(res,k,m,t):
    r0 = [0,0]
    c0 = [0,0]
    r1 = [0,0]
    c1 = [0,0]
    lastBit = k&1
    confidence = deque([],average_n)
    temp0 = [0]*sampleSize
    temp1 = [0]*sampleSize
    x=[]
    for i in range(0,sampleSize):
        x.append(res[lastBit][i][-1])
    
    for j in range(0,test_length):
        r0 = [0,0]
        c0 = [0,0]
        r1 = [0,0]
        c1 = [0,0]
        for i in range(0,sampleSize):
            temp = montMul(x[i],m[i],n,omega)
            temp1[i],red = montMulRed(temp,temp,n,omega)
            r1[red]+=t[i]
            c1[red]+=1
            
            temp0[i],red = montMulRed(x[i],x[i],n,omega)
            r0[red]+=t[i]
            c0[red]+=1
            
        u0 = abs(float(r0[1])/c0[1] - float(r0[0])/c0[0])
        u1 = abs(float(r1[1])/c1[1] - float(r1[0])/c1[0])
        confidence.append(abs(u0-u1))
        k<<=1
        if u1>u0:
            k+=1
            x,temp1 = temp1,x
        else:
            x,temp0 = temp0,x
        # If the average confidence level for the past "average_n" iterations
        # is under threshold_difference return false 
        if len(confidence)==average_n:
            if sum(confidence)/len(confidence)<threshold_difference:
                return False
                
    return True

# try going back "history_len" bits by flipping each of them one by one and test
# if that change fixed the error using test_errorFix()
def fixError (res,k,m,t):
    global errors
    errors+=1
    #remove the last partial results
    #for i in range(0,sampleSize):
    #    res[0][i].pop()
    #    res[1][i].pop()
    k<<=1 #add a random bit; will be deleted at the beginning of the loop
    print "Trying to fix the error by backtracking at most "+str(len(res[0][0]))+" bits."
    while (len(res[0][0])>1): #while I still have previous results that I can use
        
        k>>=1 #remove a bit from the key
        k^=1 #flip the last bit
        #if I have already changed that bit once, give up
        if (k&1) == initial_guess[bits(k)-1]:
            return 0, res
        #print "Removed one bit"
        #print "1011111110001100011110011001001001001010111110011101001010000101"
        print "{0:b}".format(k)
        print "==================="
        for i in range(0,sampleSize):
            res[0][i].pop() #remove the partial results corresponding to the last removed bit
            res[1][i].pop() #remove the partial results corresponding to the last removed bit
        
        if test_errorFix(res,k,m,t):
            #temp,temp,res = classify(res,m,n,omega,k&1)
            return k,res

    return 0,res
 
# The attack    
def main(m,t,res,maxLength):
    global errors, threshold_difference, initial_guess
    errors = 0
    threshold_difference = threshold_difference_init
    print "Starting the attack"
    # Temporary memory to save partial results of the exponentiation when 
    # assuming the last bit of the key is 0 or 1
    
    lastBit = 1
    key_guess = 1;
    initial_guess.append(1);
    B = 1 # number of bits in the guessed key
    H = 1 # hamming weight of the guessed key
    
    average = deque([],average_n)
    lastError = -2
    
    while (maxLength-B-H>0):
        if (maxLength-B-H<threshold_brute):
            print "Switch to brute forcing the key"
            result = brute(key_guess,B,H,maxLength)
            if result!=0:
                return result
            print "There might have been an error in the key before brute force"
            key_guess,res = fixError(res,key_guess,m,t)
            if key_guess==0:
                return -1
            else:
                threshold_difference*=1.05
                lastError = B
                B = bits(key_guess)
                H = hammingWeight(key_guess)
                average = deque([],average_n)
                lastBit = key_guess & 1
                print "FIXED"
                print "{0:b}".format(key_guess)
                continue
            
        u0,u1,res = classify(res,m,n,omega,lastBit)
        
        # If the average of abs(u0-u1) for the past 'average_n' iterations drops
        #   under 'threshold_difference' stop the attack and increase the sample
        #   size;
        # Thresholding the average for the past few iterations and not just the
        #   last result reduces the chance of getting a false positive in the
        #   error detection; I deduced this from trial and error and from the
        #   graph presented in the given paper [1]
        average.append(abs(u0-u1))
        if (len(average)==average_n) and (sum(average) < (threshold_difference * len(average))):
            #if B-lastError>5:
            #threshold_difference*=1.05
            print "Error detected. Trying to fix it"
            key_guess,res = fixError(res,key_guess,m,t)
            if key_guess!=0:
                #key_guess = ((key_guess>>2)<<1)|(key_guess&1)
                lastError = B
                B = bits(key_guess)
                H = hammingWeight(key_guess)
                average = deque([],average_n)
                lastBit = key_guess & 1
                print "FIXED"
                print "{0:b}".format(key_guess)
                
                continue
            print "The difference between deviation of means is not big enough"
            print sum(average)/average_n
            return -1
        
        # Append the guessed bit to the key and save the partial results of the 
        # exponentiation in x
        key_guess = key_guess<<1
        B+=1
        lastBit = 0
        if u1>u0:
            key_guess +=1
            H+=1
            lastBit = 1
        if B == len(initial_guess)+1:
            initial_guess.append(lastBit);
        
        print "{0:b}".format(key_guess)
    return -1
    print "Switch to brute forcing the key"
    return brute(key_guess,B,H,maxLength)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise Excepton("Incorrect number of arguments")
    exe_name = "./"+sys.argv[1]
    params_file = open(sys.argv[2])
    n = int(params_file.readline(),16)
    e = int(params_file.readline(),16)
    n_length = bits(n)
    
    #get parameters for the MontMul
    rho2 = getRho2(n)
    omega = getOmega(n)
    
    #start the oracle as a subprocess and pipe the input/output
    exe = subprocess.Popen(exe_name, 
                        stdout = subprocess.PIPE,
                        stdin = subprocess.PIPE)
    exe_in  = exe.stdin
    exe_out = exe.stdout
    
    # Get decryption time for c=0;
    # It will be used to calculate:
    # maxLength = bit_length(d)+hamming_weight(d)
    # - see bottom notes
    maxLength = oracle(0)
    maxLength = maxLength/512-1
    print "bit_length(d)+hamming_weight(d) = "+str(maxLength)
    message = random.getrandbits(n_length)
    while message>=n:
        message = random.getrandbits(n_length)
    cipher = pow(message,e,n)
    
    # Try guessing the key using 6000 samples; if it fails:
    #   1) increase the sample size by 50%
    #   2) generate new sample messages
    #   3) repeat the attack (until the sampleSize exceeds 50000)
    print "Generating "+str(sampleSize)+" sample ciphers"
    m,t,res = getRandomMessages(sampleSize) 
    key = main(m,t,res,maxLength)
    while key<1 and sampleSize<500000:
        sampleSize+=sampleSize/2 
        print "==== RESAMPLING ===\nNew sample size: "+str(sampleSize)
        m,t,res = resample(m,t,res,sampleSize)
        key = main(m,t,res,maxLength)

    if key < 1:
        print "Using over 500k sample messages did not work. This key is tricky."
    else:
        print ""
        print str(errors)+" error(s) fixed"
        print "On the following lines:\n- the key in binary\n- the key in hexadecimal\n- number of oracle calls:"
        print "{0:b}".format(key)
        print "{0:X}".format(key)
        print oracleCalls
    
    
    
