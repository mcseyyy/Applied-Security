#include <iostream>
#include <cstdlib>
#include <fstream>
#include <stdint.h>
#include <vector>
#include <cmath>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <math.h>
#include "omp.h"
#include<openssl/aes.h> 
#define byte uint8_t

#define AttacksNo 150
#define AttacksNoInc 50
#define NoTraces  1500
using namespace std;

pid_t pid        = 0;    // process ID (of either parent or child) from fork

int   target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int   attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

int interactions = 0;

void interact(byte m[AttacksNo][16], byte c[AttacksNo][16], byte trace[AttacksNo][NoTraces], int idx)
{
    int l;
    interactions++;
    for (int i=0; i<16; i++)
        fprintf( target_in, "%02X",m[idx][i]);
    fprintf(target_in,"\n");
    fflush( target_in );
    
    fscanf( target_out, "%d",&l);
    for (int i=0;i<NoTraces;i++)
    {
        fscanf( target_out, ",%hhu",&trace[idx][i]);
    }
    fscanf(target_out,"%*[^\n]");
    
    for (int i=0; i<16;i++)
    {
        fscanf( target_out, "%2hhx", &c[idx][i]);
    }
}

// HammingWeight of numbers between 0-255
// taken from http://guilherme-pg.com/2012/02/05/Weighty-Hamming-weights.html
const unsigned char HWs[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};

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

float correlation(byte traces[AttacksNo][NoTraces], byte m[AttacksNo][16], int tr, int idx, byte k)
{
    float n = AttacksNo;
    float x,y,x2,y2,xy;
    x=y=x2=y2=xy=0;
    for (int i=0;i<n;i++)
    {
        byte hw = HWs[Sbox [m[i][idx] ^ k]];
        x  += hw;
        y  += traces[i][tr];
        xy += hw*traces[i][tr];
        x2 += hw*hw;
        y2 += traces[i][tr] * traces[i][tr];
    }
    return std::abs(
        (xy-x*y/n)/
        sqrt(
            (x2-x*x/n)*(y2-y*y/n)
        )
    );
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
            if( ( target_out = fdopen( attack_raw[ 0 ], "r" ) ) == NULL ) abort();
            if( ( target_in  = fdopen( target_raw[ 1 ], "w" ) ) == NULL ) abort();
            
            byte m[AttacksNo][16];
            byte c[AttacksNo][16];
            byte traces[AttacksNo][NoTraces];
            byte keyGuess[16];
            
            for (int i=0; i<AttacksNo; i++)
            {
                for (int j=0;j<16;j++)
                {
                    do
                    {
                        m[i][j] = rand()%256;
                    }while (m[i][j]==0);
                }
                interact(m,c,traces,i);
            }
            cout<<"Finished interaction. Starting the attack\n";
            #pragma omp parallel for
            for (int ii=0; ii<16;ii++)
            {
                float bestCorr = 0;
                byte keyByte = 0;
                for (int k=0;k<256;k++)
                {
                    for (int tr=0;tr<NoTraces;tr++)
                    {
                        //float correlation(byte traces[AttacksNo][NoTraces], byte m[AttacksNo][16], int tr, int idx, byte k)
                        float corr = correlation(traces,m,tr,ii,k);
                        if (corr>bestCorr)
                        {
                            bestCorr = corr;
                            keyByte = k;
                        }
                    }
                }
                
                keyGuess[ii] = keyByte;
            }
            cout<<endl;
            byte temp[16];
            AES_KEY rk;
            AES_set_encrypt_key(keyGuess,128,&rk);
            AES_encrypt(m[0],temp,&rk);
            if( memcmp( temp, c[0], 16 * sizeof( uint8_t ) ) ) 
            {
                cout<<"Something went wrong. Try increasing AttacksNo by AttacksNoInc"<<endl;
                exit(1);
            }
            cout<<"Key recovered using "<<interactions<<" power traces\n";
            cout<<interactions<<endl;
            for (int i=0;i<16;i++)
                printf("%02X",keyGuess[i]);
            cout<<endl;
            break;
        }
    }
}