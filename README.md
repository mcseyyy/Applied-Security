## RSA and ElGamal encryption & decryption

Implemented using:
- GMP library
- Algorithms used for decreasing the running time
   - Sliding Windowed Exponentiation
   - Montgomery Multiplication
   - Chinese Remainder Theorem
   
The code is just for practice and should not be used in production

## Attacks

### Attacks agains RSA

- Timing Attack against vanilla RSA (implemented with Montgomery multiplication)
   - includes error correction techniques;
   - switches to brute-forcing the key when there are less than 15 bits to be guessed from the key;
- Attack based on error codes against RSAES-OAEP PKCS #1

### Attacks against AES

- Fault Attack
- Power Attack

Initially tried implementing them in python but it was too slow so I switched to C and parallelised them with OpenMP.

#### Notes:

- Each folder has an individual README.md that contains some description about the implementation / attack technique.
- Most of the code was written for efficiency and not readbility
- 54515.D are executables which represent the targets that have to be attacked;
- 54515.R are executables that represent replicas of the targets and that have some more options
