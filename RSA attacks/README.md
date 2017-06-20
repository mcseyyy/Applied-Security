This is the first time I have written code in python so the code might not
be (very) clean.

### Attack against RSAES-OAEP PKCS #1 based on error codes

* In the third step of the OAEP attack, when the difference between the m_min and m_max is less
  than a threshold (10-15 bits at most in python) I switch to brute forcing the
  cipher; for every bit in the difference it saves approximately one query to 
  the oracle. 
  

### Timing attack on RSA
* Any time the attack fails I increase the sample size by 50%, adding new
  messages;
  
* Using the replica I managed to find a way to estimate
  length(key)+Hamming_weight(key)
    Let:
    bits(x) = number of bits in x
    hamming(x) = hamming weight of x
    d = the private exponent
    H = hamming(d)
    B = bits(d)
    
    I assumed that the decryption time T is:
    T = Init_time + B*Square_time + H*Multiply_time + X*MontRed_time
    
    Since both squaring and multiplying are done using mont_mul =>
    MontMul_time = Multiply_time = Square_time
    When decrypting c=0 there will be no Momtgomery reduction =>
    => T = Init_time + (B+H) * MontMul_time
    
    Init_time should be just MontMul_time because it only needs to convert the
    cipher into Mont form
    
    Using the *.R oracle for calibration I found that 
    Init_time = Mont_time = 512
    
    When decrypting c=0 using the oracle, the resulting time T will be equal to:
    T = 512*(B+H+1) => B+H = T/512 - 1
    
    This result can be used to check if the partial key recovered fits the 
    model; we can stop the attack and resample when we get a key d' for which
    Hamming_weight(d') + no_of_bits(d') > B+H; 
    
    This can also be used to set a threshold where we switch to brute forcing
    the last bits of the key; this eliminates the chance of incorrectly
    guessing one of the last bits which eliminates the need of (possibly)
    increasing the sample size
    
* I implemented some basic error correction which reduced the number of samples
  needed for the given target from 5000-6000 to 2500-4000. If the deviation
  between the 2 differences is small enough I go back up to 10 bits by flipping
  each of them and testing if that change increased the confidence level.
  It is not completely robust and it is not efficient in any way but it fixes
  most of the errors.
  I have also added the code for the attack before the error correction.
  
* In order to avoid getting false alerts from the error detection mechanism I
  take into account the average deviation for the past 3-5 iterations and 
  compare that to a threshold instead of taking into account just the deviation
  for the current iteration.
  
  
Citations

    [1] Exponent Blinding May Not Prevent Timing Attacks on RSA; Werner Schindler
        https://eprint.iacr.org/2014/869.pdf
        
    [2] A Provably Secure And Efficient Countermeasure Against Timing Attacks;
        Boris Kopf and Markus Durmuth
        http://software.imdea.org/~bkoepf/papers/csf09.pdf
        
    [3] Timing Attacks on RSA: Revealing Your Secrets through the Fourth Dimension;
        Wing H. Wong
        http://www.cs.sjsu.edu/faculty/stamp/students/article.html   
        
    [4] A Chosen Ciphertext Attack on RSA OAEP as Standardized in PKCS #1 v2.0
    
    [5] PKCS #1: RSA Cryptography Specifications Version 2.0; James Manger
        http://tools.ietf.org/html/rfc2437   
    [6] A Practical Implementation of the Timing Attack; Dhem et al.
    
        http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.12.3070 



  
    
