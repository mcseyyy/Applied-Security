I used the following for implementing RSA and ElGamal:    
- Chinese Remainder Theorem (CRT)                      
- sliding window exponentiation         
- Montgomery multiplication in exponentiation

* For the sliding window exponentiation, I picked k=6 to be the window size for 
optimal efficiency; I found this result in [1] and [2];

* For generating random numbers I read 160 bits from /dev/random 
(or /dev/urandom for testing purposes) and use themas the seed for initialising 
the state for mpz_urandomb; 

* I used valgrind to check memory leaks and so far I did not observe any;
