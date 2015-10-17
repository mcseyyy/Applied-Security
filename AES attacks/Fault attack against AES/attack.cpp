#include<iostream>
#include<cstdlib>
#include<fstream>
#include<stdint.h>
#include <stdlib.h>
#include <string.h>
#include  <stdio.h>
#include  <signal.h>
#include  <unistd.h>
#include  "omp.h"
#include<openssl/aes.h> 

#define KeySize 128
#define CipherSize 
#define byte uint8_t

#define BUFFER_SIZE ( 80 )
#define R 8
#define F 1
#define P 0
#define I 0
#define J 0
using namespace std;
int interactions = 0;
int faults = 0;
pid_t pid        = 0;    // process ID (of either parent or child) from fork

int   target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int   attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

void interact(byte m[16], byte c[16], bool fault)
{
    interactions++;
    if (fault==true)
    {   
        faults++;
        fprintf( target_in, "%d,%d,%d,%d,%d\n",R,F,P,I,J);
    }
    else
        fprintf( target_in, "\n");
    fflush( target_in );
    for (int i=0;i<16;i++)
        fprintf( target_in, "%02X",m[i]);
    fprintf(target_in,"\n");
    fflush( target_in );
    
    for (int i=0;i<16;i++)
        fscanf( target_out, "%2hhx",&c[i]);
    
}


byte Mul[256][256];
byte mul(byte x, byte y)
{
    byte r=0,c;
    for (int i=0;i<8;i++)
    {
        if (y&1)
            r^=x;
        y >>=1;
        c = x&128;
        x <<= 1;
        x &= 255;
        if (c)
            x ^=27;
    }
    return r;
}

void precomputeMulTable()
{
    for (int i=0;i<256;i++)
        for (int j=0;j<256;j++)
            Mul[i][j] = mul(i,j);
}



// Rijndael S-box; taken from: taken from: http://anh.cs.luc.edu/331/code/aes.py
byte Sbox[] = {  
         0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
         0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
         0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
         0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
         0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
         0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
         0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
         0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
         0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
         0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
         0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
         0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
         0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
         0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
         0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
         0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
         
// Rijndael Inverted S-box; taken from: http://anh.cs.luc.edu/331/code/aes.py
byte RSbox[] = {
         0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
         0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
         0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
         0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
         0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
         0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
         0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
         0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
         0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
         0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
         0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
         0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
         0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
         0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
         0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
         0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// taken from: http://en.wikipedia.org/wiki/Rijndael_key_schedule
byte Rcon[] = {
         0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
         0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
         0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
         0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
         0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
         0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
         0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
         0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
         0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
         0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
         0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
         0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
         0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
         0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
         0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
         0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d};

int N[16];
 
void _inverseKey_oneRound(byte k[16], int round)
{
    k[15] ^= k[11];
    k[14] ^= k[10];
    k[13] ^=  k[9];
    k[12] ^=  k[8];
    k[11] ^=  k[7];
    k[10] ^=  k[6];
    k[9]  ^=  k[5];
    k[8]  ^=  k[4];
    k[7]  ^=  k[3];
    k[6]  ^=  k[2];
    k[5]  ^=  k[1];
    k[4]  ^=  k[0];
    k[3]  ^= Sbox[k[12]];
    k[2]  ^= Sbox[k[15]];
    k[1]  ^= Sbox[k[14]];
    k[0]  ^= Sbox[k[13]] ^ Rcon[round];
}

void inverseKey(byte k[16])
{
    for (int round = 10; round>0;round--)
    {
        _inverseKey_oneRound(k, round);
    }
}


 
void equ1(byte c[], byte cf[], byte k[16][1024])
{
    int n=0;
    for (byte delta=1; delta!=0; delta++)
    {
        byte delta2 = Mul[2][delta],
             delta3 = Mul[3][delta];
             
        byte k0 = 0;
        do// for (byte k0 = 0; k0<256;k0++)
        {
            if (delta2 != (RSbox[c[0]^k0]^RSbox[cf[0]^k0]))
                continue;
            byte k13 = 0;
            do //for (byte k13 = 0; k13<255; k13++)
            {
                if (delta != (RSbox[c[13]^k13]^RSbox[cf[13]^k13]))
                    continue;
                byte k10 = 0;
                do //for (byte k10 = 0; k10<256; k10++)
                {
                    if (delta != (RSbox[c[10]^k10] ^ RSbox[cf[10]^k10]) )
                        continue;
                    byte k7 = 0;
                    do //for (byte k7 = 0; k7<256;k7++)
                    {
                        if (delta3 == (RSbox[c[7]^k7]^RSbox[cf[7]^k7]))
                        {
                            k[0][n]  = k0;
                            k[7][n]  = k7;
                            k[10][n] = k10;
                            k[13][n] = k13;
                            n++;
                        }
                    }while (++k7!=0);
                }while (++k10!=0);
            }while (++k13!=0);
        } while (++k0!=0);
    }
    N[0]=N[7]=N[10]=N[13] = n;
}

void equ2(byte c[], byte cf[], byte k[16][1024])
{
    int n=0;
    for (byte delta=1; delta!=0; delta++)
    {
        byte delta2 = Mul[2][delta],
             delta3 = Mul[3][delta];
             
        byte k4 = 0;
        do{
            if (delta != (RSbox[c[4]^k4]^RSbox[cf[4]^k4]))
                continue;
            byte k1 = 0;
            do{
                if (delta != (RSbox[c[1]^k1]^RSbox[cf[1]^k1]))
                    continue;
                byte k14 = 0;
                do{
                    if (delta3 != (RSbox[c[14]^k14]^RSbox[cf[14]^k14]))
                        continue;
                    byte k11 = 0;
                    do{
                        if (delta2 == (RSbox[c[11]^k11]^RSbox[cf[11]^k11]))
                        {
                            k[1][n]  = k1;
                            k[4][n]  = k4;
                            k[11][n] = k11;
                            k[14][n] = k14;
                            n++;
                        }
                    }while (++k11!=0);
                }while (++k14!=0);
            }while (++k1!=0);
        } while (++k4!=0);
    }
    N[1]=N[4]=N[11]=N[14] = n;
}

void equ3(byte c[], byte cf[], byte k[16][1024])
{
    int n=0;
    for (byte delta=1; delta!=0; delta++)
    {
        byte delta2 = Mul[2][delta],
             delta3 = Mul[3][delta];
             
        byte k8 = 0;
        do{
            if (delta != (RSbox[c[8]^k8]^RSbox[cf[8]^k8]))
                continue;
            byte k5 = 0;
            do{
                if (delta3 != (RSbox[c[5]^k5]^RSbox[cf[5]^k5]))
                    continue;
                byte k2 = 0;
                do{
                    if (delta2 != (RSbox[c[2]^k2]^RSbox[cf[2]^k2]))
                        continue;
                    byte k15 = 0;
                    do{
                        if (delta == (RSbox[c[15]^k15]^RSbox[cf[15]^k15]))
                        {
                            k[2][n]  = k2;
                            k[5][n]  = k5;
                            k[8][n]  = k8;
                            k[15][n] = k15;
                            n++;
                        }
                    }while (++k15!=0);
                }while (++k2!=0);
            }while (++k5!=0);
        } while (++k8!=0);
    }
    N[2]=N[5]=N[8]=N[15] = n;
}

void equ4(byte c[], byte cf[], byte k[16][1024])
{
    int n=0;
    for (byte delta=1; delta!=0; delta++)
    {
        byte delta2 = Mul[2][delta],
             delta3 = Mul[3][delta];
             
        byte k12 = 0;
        do{
            if (delta3 != (RSbox[c[12]^k12]^RSbox[cf[12]^k12]))
                continue;
            byte k9 = 0;
            do{
                if (delta2 != (RSbox[c[9]^k9]^RSbox[cf[9]^k9]))
                    continue;
                byte k6 = 0;
                do{
                    if (delta != (RSbox[c[6]^k6]^RSbox[cf[6]^k6]))
                        continue;
                    byte k3 = 0;
                    do{
                        if (delta == (RSbox[c[3]^k3]^RSbox[cf[3]^k3]))
                        {
                            k[3][n]  = k3;
                            k[6][n]  = k6;
                            k[9][n]  = k9;
                            k[12][n] = k12;
                            n++;
                        }
                    }while (++k3!=0);
                }while (++k6!=0);
            }while (++k9!=0);
        } while (++k12!=0);
    }
    N[3]=N[6]=N[9]=N[12] = n;
}

byte equf1(byte k[], byte kp[], byte c[], byte cf[])
{
    return 
    RSbox[
          Mul[ RSbox[c[0]  ^ k[0 ] ] ^ kp[0] ][14]
        ^ Mul[ RSbox[c[13] ^ k[13] ] ^ kp[1] ][11]
        ^ Mul[ RSbox[c[10] ^ k[10] ] ^ kp[2] ][13]
        ^ Mul[ RSbox[c[7]  ^ k[7 ] ] ^ kp[3] ][9 ]
    ] ^
    RSbox[
          Mul[ RSbox[cf[0]  ^ k[0 ] ] ^ kp[0] ][14]
        ^ Mul[ RSbox[cf[13] ^ k[13] ] ^ kp[1] ][11]
        ^ Mul[ RSbox[cf[10] ^ k[10] ] ^ kp[2] ][13]
        ^ Mul[ RSbox[cf[7]  ^ k[7 ] ] ^ kp[3] ][9 ]
    ];
}

byte equf2(byte k[], byte kp[], byte c[], byte cf[])
{
    return
    RSbox[
          Mul[ RSbox[c[12]^k[12]] ^ kp[12] ][9 ]
        ^ Mul[ RSbox[c[9] ^k[9] ] ^ kp[13] ][14]
        ^ Mul[ RSbox[c[6] ^k[6] ] ^ kp[14] ][11]
        ^ Mul[ RSbox[c[3] ^k[3] ] ^ kp[15] ][13]
    ] ^
    RSbox[
          Mul[ RSbox[cf[12]^k[12]] ^ kp[12] ][9 ]
        ^ Mul[ RSbox[cf[9] ^k[9] ] ^ kp[13] ][14]
        ^ Mul[ RSbox[cf[6] ^k[6] ] ^ kp[14] ][11]
        ^ Mul[ RSbox[cf[3] ^k[3] ] ^ kp[15] ][13]
    ];
}

byte equf3(byte k[], byte kp[], byte c[], byte cf[])
{
    return 
    RSbox[
          Mul[ RSbox[c[8]  ^ k[8]  ]  ^ kp[8]  ][13]
        ^ Mul[ RSbox[c[5]  ^ k[5]  ]  ^ kp[9]  ][9 ]
        ^ Mul[ RSbox[c[2]  ^ k[2]  ]  ^ kp[10] ][14]
        ^ Mul[ RSbox[c[15] ^ k[15] ]  ^ kp[11] ][11]
    ] ^ 
    RSbox[
          Mul[ RSbox[cf[8]  ^ k[8]  ]  ^ kp[8]  ][13]
        ^ Mul[ RSbox[cf[5]  ^ k[5]  ]  ^ kp[9]  ][9 ]
        ^ Mul[ RSbox[cf[2]  ^ k[2]  ]  ^ kp[10] ][14]
        ^ Mul[ RSbox[cf[15] ^ k[15] ]  ^ kp[11] ][11]
    ];
}

byte equf4(byte k[], byte kp[], byte c[], byte cf[])
{
    return 
    RSbox[
          Mul[ RSbox[c[4]  ^ k[4]  ]  ^ kp[4] ][11]
        ^ Mul[ RSbox[c[1]  ^ k[1]  ]  ^ kp[5] ][13]
        ^ Mul[ RSbox[c[14] ^ k[14] ]  ^ kp[6] ][9 ]
        ^ Mul[ RSbox[c[11] ^ k[11] ]  ^ kp[7] ][14]
    ] ^ 
    RSbox[
          Mul[ RSbox[cf[4]  ^ k[4]  ]  ^ kp[4] ][11]
        ^ Mul[ RSbox[cf[1]  ^ k[1]  ]  ^ kp[5] ][13]
        ^ Mul[ RSbox[cf[14] ^ k[14] ]  ^ kp[6] ][9 ]
        ^ Mul[ RSbox[cf[11] ^ k[11] ]  ^ kp[7] ][14]
    ];

}



int part2(byte kk[16][1024], byte c[], byte cf[], byte m[])
{   int count = 0;
    #pragma omp parallel for
    for (int i1 = 0; i1<=N[0]; i1++)
    { 
        if (!(i1%10))
            cout<<"."<<endl;
        for (int i2 = 0; i2<=N[1]; i2++)
            for (int i3 = 0; i3<=N[2]; i3++)
                for (int i4 = 1; i4<N[3]; i4++)
                {
                    byte f;
                    byte temp[16];
                    byte  k[] = {kk[0][i1],kk[1][i2],kk[2][i3],kk[3][i4],kk[4][i2],kk[5][i3],kk[6][i4],kk[7][i1],kk[8][i3],kk[9][i4],kk[10][i1],kk[11][i2],kk[12][i4],kk[13][i1],kk[14][i2],kk[15][i3]};
                    byte kp[] = {kk[0][i1],kk[1][i2],kk[2][i3],kk[3][i4],kk[4][i2],kk[5][i3],kk[6][i4],kk[7][i1],kk[8][i3],kk[9][i4],kk[10][i1],kk[11][i2],kk[12][i4],kk[13][i1],kk[14][i2],kk[15][i3]};                
                    
                    _inverseKey_oneRound(kp,10);
                    f = equf2(k,kp,c,cf);
                    if (f != equf3(k,kp,c,cf))
                        continue;
                    if (Mul[f][2]!= equf1(k,kp,c,cf))
                        continue;
                    if (Mul[f][3]!= equf4(k,kp,c,cf))
                        continue;
                    count++;
                    inverseKey(k);
                    AES_KEY rk;
                    AES_set_encrypt_key( k, 128, &rk );
                    AES_encrypt( m, temp, &rk );  
                    if( !memcmp( temp, c, 16 * sizeof( uint8_t ) ) ) 
                    {
                        cout<<endl<<"Found the key using "<<interactions<<" interactions out of which "<<faults<<" had faults inserted"<<endl;
                        cout<<interactions<<endl;
                        for (int i=0;i<16;i++)
                            printf("%02X",k[i]);
                        cout<<endl;
                        exit(0);
                    }
                }
    }
    return count;
}

void cleanup( int s ){
    s++;s--;
    fclose( target_in  );
    fclose( target_out );
    close( target_raw[ 0 ] ); 
    close( target_raw[ 1 ] ); 
    close( attack_raw[ 0 ] ); 
    close( attack_raw[ 1 ] ); 
    if( pid > 0 ) 
        kill( pid, SIGKILL );
    exit( 1 ); 
}
 
int main( int argc, char* argv[] ) {
    for(;argc;)break; //this is here just to get rid of "unused argc" warning
    signal( SIGINT, &cleanup );
    if( pipe( target_raw ) == -1 )
        abort();
    if( pipe( attack_raw ) == -1 )
        abort();
    switch( pid = fork() )
    { 
        case -1 : 
            abort();
        
        case +0 : 
        {
            close( STDOUT_FILENO );
            if( dup2( attack_raw[ 1 ], STDOUT_FILENO ) == -1 )
                abort();
            close(  STDIN_FILENO );
            if( dup2( target_raw[ 0 ],  STDIN_FILENO ) == -1 ) 
                abort();
            execl( &(string("./") + argv[1])[0], (const char*)NULL,(char*)NULL );
            break;
        }
        
        default : 
        {
            if( ( target_out = fdopen( attack_raw[ 0 ], "r" ) ) == NULL )
                abort();
            
            if( ( target_in  = fdopen( target_raw[ 1 ], "w" ) ) == NULL ) 
                abort();
            while (true) //if the key is found the program exits directly
            {
                byte m[16],c[16],cf[16];
                precomputeMulTable();
                for (int i=0;i<16;i++)
                    do
                        m[i] = rand()%256;
                    while (m[i]==0);    
                interact(m,c,false);
                interact(m,cf,true);
                
                byte key_guess[16][1024];
                
                
                equ1(c,cf,key_guess);
                equ2(c,cf,key_guess);
                equ3(c,cf,key_guess);
                equ4(c,cf,key_guess);
                cout<<"Finished first set of equations\nGenerated ";
                printf("%d x %d x %d x %d key hypothesis after first set of equations\n",N[0],N[1],N[2],N[3]);
                cout<<"Testing them using second set of equations"<<endl;
                part2(key_guess,c,cf,m);
            }
    
            break;
        }
    }
}