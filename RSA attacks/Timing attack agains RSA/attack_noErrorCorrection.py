#!/usr/bin/python
import subprocess, math, hashlib, binascii, sys, random
from decryption import getRho2, getOmega, montMul, montMulRed, bits
sampleSize = 6000 # initial number of sample cyphers generated for the attack
n_length = 1024 # this value will be overriden when n is read from params file
threshold_difference  = 0.001#0.9
threshold_individual = 0.001#1.999

# Call the oracle to get the decryption time of a given cypher
def oracle(c):
    exe_in.write("{0:0256x}\n".format(c))
    time = int(exe_out.readline().strip())
    deceyphered_message = exe_out.readline()
    return time

# Call the oracle to get the decryption of a given cypher    
def decrypt(c):
    exe_in.write("{0:0256x}\n".format(c))
    time = exe_out.readline()
    decipher = int(exe_out.readline().strip(),16)
    return decipher
    
                    
# Function that tests if the guessed key is correct
def testKey(k):
    if randomMessage_dec == pow(randomMessage,k,n):
        return True
    return False

def getRandomMessages():
    messages = [] # save the sample cyphers in Mont form
    times = []    # time taken to decrypt the cypher
    x = []        # temporary memory to save the partial result of the partial exponentiation
    for i in range (0,sampleSize):
        if i%1500==0:
            print i
        r = random.getrandbits(n_length)
        while r>=n:
            r = random.getrandbits(n_length)
        times.append(oracle(r))
        messages.append(montMul(r,rho2,n,omega)) #convert the message in Mont form and add it to the list
        x.append(messages[i])
        x[i] = montMul(x[i],x[i],n,omega)
    print "done generating random messages"
    return messages,times,x;

def main(n,e):
    m,t,x = getRandomMessages() # get the random ciphers (in Mont form), 
                                # corresponding times and partial results of the 
                                # partial exponentiation
    # Temporary memory to save partial results of the exponentiation when 
    # assuming the last bit of the key is 0 or 1
    res1 = [0]*sampleSize 
    res0 = [0]*sampleSize
    
    key_guess = 1;
    B = 1 #number of bits in the guessed key
    H = 1 #hamming weight of the guessed key
    
    while B+H < maxLength:
        print B
        # Initialise the subsets to empty lists and the counters to 0
        # (for each subset)
        r0 = [0,0]
        c0 = [0,0]
        r1 = [0,0]
        c1 = [0,0]
        
        # Classify each message depending if there was a reduction or not
        for i in range(0,sampleSize):
            # assuming that the bit is 1
            res1[i] = montMul(x[i],m[i],n,omega) #multiplication 
            res1[i],red = montMulRed(res1[i],res1[i],n,omega) #squaring
            r1[red]+=t[i]
            c1[red]+=1
            
            #assuming that the bit is 0
            res0[i],red = montMulRed(x[i],x[i],n,omega) #squaring
            r0[red]+=t[i]
            c0[red]+=1
       
        # Calculate the difference between the average times when we assume that
        # last bit is 0 and when the last bit is 1
        u1 = abs(float(r1[1])/c1[1] - float(r1[0])/c1[0])
        u0 = abs(float(r0[1])/c0[1] - float(r0[0])/c0[0])

        
        
        # some threshold conditions
        if abs(u0-u1)<threshold_difference:
            print "The difference between deviation of means is not big enough"
            return -1
        if u1>u0 and u1<threshold_individual:
            print "The timing difference between M1 and M2 is not big enough"
   
            return -1
        if u0>u1 and u0<threshold_individual:
            print "The timing difference between M3 and M4 is not big enough"

            return -1
        
        # Append the guessed bit to the key and save the partial results of the 
        # exponentiation in x and save the partial results in x
        key_guess = key_guess<<1
        if u1>u0:
            key_guess +=1
            H+=1
            x,res1 = res1,x
        else:
            x,res0 = res0,x
        B+=1
            
        # Test the key by appending a '1' to it
        # The last bit of d is '1' because gcd(d,phi(N)) = 1
        key_temp = (key_guess<<1) | 1
        if testKey(key_temp):
            return key_temp
        print "1011111110001100011110011001001001001010111110011101001010000101"
        print "{0:b}".format(key_guess)
        print "B="+str(B)+" H="+str(H)
    return -1
    
 

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise Excepton("Incorrect number of arguments")
    exe_name = "./"+sys.argv[1]
    params_file = open(sys.argv[2])
    n = int(params_file.readline(),16)
    e = int(params_file.readline(),16)
    n_length = bits(n)
    
    #get parameters for the Mont multiplication
    rho2 = getRho2(n)
    omega = getOmega(n)
    
    #start the oracle as a subprocess and pipe the input/output
    exe = subprocess.Popen(exe_name, 
                        stdout = subprocess.PIPE,
                        stdin = subprocess.PIPE)
    exe_in  = exe.stdin
    exe_out = exe.stdout
    
    # Generate a random cypher and decrypt it; it will be used to test if the
    # generated/guessed key is valid or not
    maxLength = oracle(0)
    maxLength = maxLength/512-1
    print maxLength
    randomMessage = random.getrandbits(n_length)
    while randomMessage>=n:
        randomMessage = random.getrandbits(n_length)
    randomMessage_dec = decrypt(randomMessage)
    
    # Try guessing the key using 6000 samples; if it fails:
    #   1) increase the sample size by 50%
    #   2) generate new sample messages
    #   3) repeat the attack (until the sampleSize exceeds 50000)
    key = main(n,e)

    while key==-1 and sampleSize<50000:
        print "==== RESAMPLING ==="
        sampleSize+=sampleSize/2
        key = main(n,e)

    if key == -1:
        print "Using 45563 sample messages did not work. This key is tricky." 
        print "The key might have more than 1024 bits"
    else:
        print "{0:b}".format(key)
        print key
        
        
    # Let:
    #    bits(x) = number of bits in x
    #    hamming(x) = hamming weight of x
    #    d = the private exponent
    #    H = hamming(d)
    #    B = bits(d)
    # 
    # I assumed that the decryption time T is:
    # T = Init_time + B*Square_time + H*Multiply_time + X*MontRed_time
    #
    # Since both squaring and multiplying are done using mont_mul =>
    # MontMul_time = Multiply_time = Square_time
    # When decrypting c=0 there will be no Momtgomery reduction =>
    # => T = Init_time + (B+H) * MontMul_time
    #
    # Using the *.R oracle for calibration I found that 
    # Init_time = Mont_time = 512
    #
    # When decrypting c=0 using the oracle, the resulting time T will be equal to:
    # T = 512*(B+H+1) => B+H = T/512 - 1
    #
    # This result can be used to check if the partial key recovered fits the 
    # model; we can stop the attack and resample when we get a key d' for which
    # Hamming_weight(d') + no_of_bits(d') > B+H
    
    
    
