#include "modmul.h"
#define max(a, b) ((a) > (b) ? (a) : (b))
#define DBG
//constants for windowed exponentiations
#define logBase  6
#define base 64
#define bpl mp_bits_per_limb

//DEFINE: destructive function
// - a destructive function needs the input variables to be different from the 
//   output variable;

// NOTE:
// Since quite a few of my functions are destructive, some of my variables were 
// defined as arrays with 2 indexes that are used alternatively as main memory 
// and temp memory;

void debug(char *err)
{
    #ifdef DBG
        printf("%s\n",err);
        fflush(NULL);
    #endif
    return;
}

//get a 160 bits from /dev/(u)random and save them in 'seed'
void getSeed(mpz_t seed)
{
    char buffer[21];
    FILE *input = fopen("/dev/random","r");
    //FILE *input = fopen("/dev/urandom","r");
    fscanf(input,"%20s",buffer);            //Get 160 random bytes for the seed
    mpz_import(seed, 20, -1,1,-1,0,buffer); //20 (chars) * 8 (bits/char) = 160 bits
    fclose(input);
}


//get i-th bits from x; small <= i <= big; big-small+1 <= 32
unsigned int getBitsRange(mpz_t x, unsigned int big, unsigned int small)
{
    unsigned int mask = (1<<(big-small+1))-1;
    mpz_t temp;
    mpz_init(temp);
    mpz_tdiv_q_2exp(temp,x,small); //right shift
    mask = mpz_get_ui(temp) & mask;
    mpz_clear(temp);
    return mask;
}

// Given n, it returns Omega for Montgomery multiplication
mp_limb_t get_omega(mpz_t n)
{
    mp_limb_t t=1,
        n0 = mpz_getlimbn(n,0);
    for (int i=1; i < bpl; i++)
        t = t*t*n0; //(mod b) is implicit 
    t=-t;
    return t;
}

// Computes rho^2 % n for a given n and saves the value in t
void get_rho2(mpz_t t,mpz_t n)
{
    unsigned int lN = mpz_size(n);
    mpz_set_ui(t,1);
    
    for (int i=1; i <= 2*lN*bpl;i++)
    {
        mpz_add (t,t,t);
        if (mpz_cmp(t,n)>=0)
            mpz_sub(t,t,n);
    } 
}

// Decodes a number from Montgomery form
// The same as mont_mul(r,x,y=1,w,N) but y=1 is hard-coded in the function
// in order to optimise it;
// *destructive function*
void mont_decode(mpz_t r, mpz_t x, mp_limb_t w, mpz_t N)
{
    mp_limb_t x0 = mpz_getlimbn(x,0),r0;
    mpz_t uN;
    mpz_init(uN);
              
    mpz_mul_ui(uN,N,x0*w);
    mpz_add(r,x,uN);
    mpz_tdiv_q_2exp(r,r,bpl);
    
    if (mpz_cmp(r,N)>=0)
        mpz_sub(r,r,N);
    
    for (int i=1;i<mpz_size(N);i++)
    {
        r0 = mpz_getlimbn(r,0);
        
        
        mpz_mul_ui(uN,N,r0*w);
        mpz_add(r,r,uN);
        mpz_tdiv_q_2exp(r,r,bpl);
        
        if(mpz_cmp(r,N)>=0)
            mpz_sub(r,r,N);
    }
    mpz_clear(uN);
    
}

// given 0 <= x,y < N the function computes r= x * y * rho^(-1) % N
// *destructive function*
void mont_mul(mpz_t r, mpz_t x, mpz_t y, mp_limb_t w, mpz_t N)
{   
    mpz_set_ui(r,0);
    mp_limb_t u,r0,yi,
        x0 = mpz_getlimbn(x,0);
        
    mpz_t uN, yix;
    mpz_inits(uN, yix,NULL);
    
    for (int i=0; i < mpz_size(N); i++)
    {
        
        yi = mpz_getlimbn(y,i); 
        r0 = mpz_getlimbn(r,0);
        u = (r0 + yi * x0) * w;
        
        mpz_mul_ui(uN,N,u);
        mpz_mul_ui(yix,x,yi);
        
        mpz_add(r,r,yix);
        mpz_add(r,r,uN);
        mpz_tdiv_q_2exp(r,r,bpl); //bitshift to the right by bpl bits; r=r/2^64
        
        if (mpz_cmp(r,N)>=0)
            mpz_sub(r,r,N);
    }
    
    mpz_clears(uN,yix,NULL);
}

// Given t,n,omega,rho^2 it computes (t * rho) % n using Mont reduction
// Use only when t >= N; otherwise mont_mul(r,t,rho^2) is faster
// *destructive function*
void mont_red(mpz_t r, mpz_t t, mpz_t N, mp_limb_t w, mpz_t rho2)
{
    mpz_t b,uNb;
    mpz_init (uNb);
    mpz_init_set_ui(b,1);
    mpz_set(r,t);
    mp_limb_t u;
    for (int i=0;i<mpz_size(N); ++i)
    {   
        u = mpz_getlimbn(r,i) * w;
        mpz_mul_ui(uNb,N,u);
        mpz_mul(uNb, uNb, b);
        mpz_add(r,r,uNb);
        mpz_mul_2exp(b,b,64); //left shift by 64 bits
    }
    mpz_tdiv_q_2exp(r,r,mpz_size(N)*bpl);
    
    if (mpz_cmp(r,N)>=0)
        mpz_sub(r,r,N);
    // At this point r = r * rho^(-1) % n
     
        
    // Encode in Montgomery form by multiplying r with rho2 twice
    mont_mul(uNb,r,rho2,w,N);   // unB = r * rho % N
    mont_mul(r,uNb,rho2,w,N);   // r = uNb * rho % N
    
    mpz_clears(b, uNb,NULL);
} 

//initialising temporary memory for windowed exponentiation
void mpz_initExp(mpz_t t[], mpz_t x2)
{
    mpz_init(x2);
    for (int i=0;i<base/2;i++)
        mpz_init(t[i]);
    return;
}

//clearing the temporary memory used in windowed exponentiation
void mpz_clearExp(mpz_t t[], mpz_t x2)
{
    mpz_clear(x2);
    for (int i=0;i<base/2;i++)
        mpz_clear(t[i]);
    return;
}


// Computes t[0]^y % n
// Stores the result in r[0] in Montgomery form; r has to be an array of size = 2
// t[0] needs to be in Montgomery form; the array has size = base/2
// x2 is temporary memory
// rho2 and w (omega) are parameters of the mont_mul
// *destructive function*
void window_expm(mpz_t r[], mpz_t t[], mpz_t y, mpz_t n, mpz_t x2, mpz_t rho2, mp_limb_t w)
{
    mpz_t one;
    mpz_init_set_ui(one,1);
    mont_mul(r[0],one,rho2,w,n); //convert 1 to Montgomery form
    mont_mul(x2,t[0],t[0],w,n);
    
    // Precomputation of T[]
    for (int i=1;i<base/2;i++)
        mont_mul(t[i],t[i-1],x2,w,n);
    
    int i = mpz_size(y)*mp_bits_per_limb-1,
        l;
    unsigned int u;
     
    while (i>=0)
    {
        if (!mpz_tstbit(y,i))
        {
            l=i;
            u=0;
        }
        else
        {   
            l = max(i-logBase+1,0);
            //find the first non-zero bit
            while (!mpz_tstbit(y,l))
                l++;
            u = getBitsRange(y,i,l);
        }
        
        // r = r ^ (2 ^ (i-l+t))
        for (int j=0; j<i-l+1; j++)
            mont_mul(r[(j+1)%2],r[j%2],r[j%2],w,n);
        
        if ((i-l+1) % 2) //making sure that the result of the exponentiation is in r[0]
            mpz_set(r[0],r[1]);
        
        if (u)
        {
            mpz_set(r[1],r[0]);
            mont_mul(r[0],r[1],t[(u-1)/2],w,n); //r = r * t[(u-1)/2]
        }
        i=l-1;
    }
    mpz_clear(one);
}


/*
----- Perform stage 1:
- read each 3-tuple of N, e and m from stdin,
- compute the RSA encryption c,
- then write the ciphertext c to stdout.
-*/
void stage1()
{
    mpz_t n,e,m,c[2];
    mpz_t t[base/2],x2,rho2,one;
    mp_limb_t w;  //* parameter of the Montgomery multiplcation
    
    mpz_inits(
        n,     //* 1024 bit modulus
        e,     //* public exponent
        m,     //* message to be encrypted 0 <= m < N
        c[0],  //* cipher; c = (m ^ e) % N
        c[1],  //* temporary memory used in windowed exponentiation
        rho2,  //* parameter of the Montgomery multiplcation
        NULL);
    
    mpz_initExp(t,x2);
    mpz_init_set_ui(one,1);
    
    while (gmp_scanf("%Zx\n%Zx\n%Zx\n",&n,&e,&m) > 0)
    {
        get_rho2(rho2,n);
        w = get_omega(n);
        
        mont_mul(t[0],m,rho2,w,n); //convert m
        window_expm(c,t,e,n,x2,rho2,w); //c=(m^e)%n;
        mont_decode(c[1], c[0], w, n); //decode c
        
        gmp_printf("%ZX\n",c[1]);                   
    }
    
    mpz_clears(n,e,m,c[0],c[1],one,rho2,NULL);
    mpz_clearExp(t,x2);
    return;
}

/*
----- Perform stage 2:
- read each 9-tuple of N, d, p, q, d_p, d_q, i_p, i_q and c from stdin,
- compute the RSA decryption m,
- then write the plaintext m to stdout.
*/
void stage2()
{
    mpz_t n, d, p, q, dp, dq, ip, iq, c, x, xp[2], xq[2], 
          rho2,t[base/2],x2; //parameters for mont_mul or window_exp
    mp_limb_t w; //* parameter of the Montgomery multiplcation    
    mpz_inits(
        n,      //* 1024 bit modulus  n = p * q
        d,      //* private exponent
        p,      //* 512 bit prime     n = p * q
        q,      //* 512 bit prime     n = p * q
        dp,     //* dp = d % (p-1)
        dq,     //* dq = d & (q-1)
        ip,     //* inverse of p;  ip = (p ^ (-1)) % q
        iq,     //* inverse of q;  iq = (q ^ (-1)) % p
        c,      //* cipher to be decrypted;  0 <= c < N
        x,      //* message; x = (c^d) % n
        xp[0],  //* xp = (c^dp % p) * q * iq
        xp[1],  //* temp memory for windowed exp
        xq[0],  //* xq = (c^dq % q) * p * ip
        xq[1],  //* temp memory for windowed exp
        rho2,   //* parameter of the Montgomery multiplcation
        NULL);
    mpz_initExp(t,x2);
    
    while(gmp_scanf("%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n%Zx\n",&n,&d,&p,&q,&dp,&dq,&ip,&iq,&c) > 0)
    {   
        get_rho2(rho2,p);
        w = get_omega(p);
        
        mont_red(t[0],c,p,w,rho2);         // encode c
        window_expm(xp,t,dp,p,x2,rho2,w);  // xp[0] = t[0]^dp % p [in Mont representation]
        mont_decode(xp[1],xp[0],w,p);      // decode xp
                                              
        get_rho2(rho2,q);                     
        w = get_omega(q);                     
        mont_red(t[0],c,q,w,rho2);         // encode c
        window_expm(xq,t,dq,q,x2,rho2,w);  // xq[0] = t[0]^dq % q [in Mont representation]
        mont_decode(xq[1],xq[0],w,q);      // decode xq
        
        // Encoding everything back in Montgomery form (with modulus N) would 
        // probably take longer than normal multiplication taking into account
        // that there are just a few multiplications;
        
        mpz_mul(xp[1],xp[1],q);     // xp = xp * q
        mpz_mod(xp[1],xp[1],n);     // xp = xp % n 
        mpz_mul(xq[1],xq[1],p);     // xq = xq * p
        mpz_mod(xq[1],xq[1],n);     // xq = xq % n
        
        mpz_mul(xp[1],xp[1],iq);    // xp = xp * iq
        mpz_mod(xp[1],xp[1],n);     // xp = xp % n
                                       
        mpz_mul(xq[1],xq[1],ip);    // xq = xq * ip
        mpz_mod(xq[1],xq[1],n);     // xq = xq % n
        
        mpz_add(xp[1],xp[1],xq[1]); // xp = xp + xq
        mpz_mod(xp[1],xp[1],n);     // xp = xp % n
        
        gmp_printf("%ZX\n",xp[1]);
    }
    
    mpz_clears(n,d,p,q,dp,dq,ip,iq,c,x,xp[0],xp[1],xq[0],xq[1],rho2,NULL);
    mpz_clearExp(t,x2);
    return;
}

/*
----- Perform stage 3:
- read each 5-tuple of p, q, g, h and m from stdin,
- compute the ElGamal encryption c = (c_1,c_2),
- then write the ciphertext c to stdout.
*/
void stage3()
{
    mpz_t p,q,g,h,m,c1[2],c2[2],r,m_mont; 
    mpz_t t[base/2],x2,rho2;
    mp_limb_t w; //* parameter of the Montgomery multiplication
    
    mpz_t seed;
    mpz_init(seed);
    getSeed(seed);
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed(state,seed);
    mpz_clear(seed);
    
    mpz_inits(
        p,      //* 1024 bit large modulus
        q,      //* 160 bit small modulus
        g,      //* generator of Fp with order q
        h,      //* public key
        m,      //* message; 0 <= m < p
        m_mont,
        c1[0],  //* cipher 1  ; c1 = (g ^ (r%q)) % p
        c1[1],  //*
        c2[0],  //* cipher 2  ; c2 = (m * (h ^ (r%1))) % p
        c2[1],  //*
        r,      //* random number ; r = rand() % q
        rho2,   //* parameter of the Montgomery multiplication
        NULL);
    
    mpz_initExp(t,x2);
    
    
    while (gmp_scanf("%ZX\n%ZX\n%ZX\n%ZX\n%ZX\n",&p,&q,&g,&h,&m) > 0)
    {   
        mpz_urandomb(r,state,160);
        //mpz_set_ui(r,1);
        mpz_mod(r,r,q); //r=r%q
        
        get_rho2(rho2,p);
        w = get_omega(p);
        
        mont_mul(t[0],g,rho2,w,p);       //encode g
        window_expm(c1,t,r,p,x2,rho2,w); // c1 = (g ^ r) % p
        mont_decode(c1[1],c1[0],w,p);    //decode c1
        
        mont_mul(t[0],h,rho2,w,p);       // encode h
        window_expm(c2,t,r,p,x2,rho2,w); // c2 = (h ^ r) % p
        
        mont_mul(m_mont,m,rho2,w,p);      //encode m
        mont_mul(c2[1],c2[0],m_mont,w,p); //c2 = c2 * m % p 
        mont_decode(c2[0],c2[1],w,p);    //decode c2
                
        gmp_printf("%ZX\n%ZX\n",c1[1],c2[0]);
    }

    mpz_clears(p,q,g,h,m,m_mont,c1[0],c1[1],c2[0],c2[1],r,rho2,NULL);
    mpz_clearExp(t,x2);
    gmp_randclear(state);
    
    return;
}

/*
----- Perform stage 4:
- read each 5-tuple of p, q, g, x and c = (c_1,c_2) from stdin,
- compute the ElGamal decryption m,
- then write the plaintext m to stdout.
*/
void stage4() 
{
    mpz_t p,q,g,x,c1,c2,c2_mont,m[2];
    mpz_t t[base/2],x2,rho2;
    mp_limb_t w; //* parameter of the Montgomery multiplcation
    
    mpz_inits(
        p,      //* 1024 bit large modulus
        q,      //* 160 bit small modulus
        g,      //* generator Fp with order q
        x,      //* private key
        c1,     //* cipher 1; 0 <= c1 <p
        c2,     //* cipher 2; 0 <= c2 <p
        c2_mont,//* cipher 2 in Montgomery form
        m[0],   //* decrypted message
        m[1],   //*
        rho2,   //* parameter of the Montgomery multiplcation
        NULL);
    mpz_initExp(t,x2);
    
    
    while (gmp_scanf("%ZX\n%ZX\n%ZX\n%ZX\n%ZX\n%ZX\n",&p,&q,&g,&x,&c1,&c2) > 0)
    {   
        //x = (-x) % q
        mpz_mod(x,x,q); // x = x % q 
        mpz_sub(x,q,x); // x = q - x
        
        get_rho2(rho2,p);
        w = get_omega(p);
        mont_mul(t[0],c1,rho2,w,p);     // encode c1
        window_expm(m,t,x,p,x2,rho2,w); // m = (c1 ^ x) % p
                                           
        mont_mul(c2_mont,c2,rho2,w,p);  // encode c2
        mont_mul(m[1],m[0],c2_mont,w,p);// m[1] = m[0] * c2_mont
        mont_decode(m[0],m[1],w,p);     // decode m
        
        gmp_printf("%ZX\n",m[0]);
    }
    
    mpz_clears(p,q,g,x,c1,c2,c2_mont,m[0],m[1],rho2,NULL);
    mpz_clearExp(t,x2);
    
    return;
}


//** Function used for testing; might not work in the final version */

//void testMont()
//{
//    mpz_t rho2,n,x,y,x1,y1,r1,r,one;
//    mpz_inits(rho2,n,x,y,x1,y1,r1,r,one,NULL);
//    
//    gmp_scanf("%Zd %Zd %Zd",&x,&y,&n);
//    gmp_printf("x=%Zd\ny=%Zd\nn=%Zd\n",x,y,n);
//    mpz_set_ui(one,1);
//    
//    get_rho2(rho2,n);
//    mp_limb_t w = get_omega(n);
//    
//    gmp_printf("rho2 = %Zd\n", rho2);
//    printf("omega = %lu\n", w);
//    
//    
//    mont_mul(x1,x,rho2,w,n);
//    gmp_printf("x1 = %Zd\n",x1);
//    
//    mont_mul(y1,y,rho2,w,n);
//    gmp_printf("y1 = %Zd\n",y1);
//    
//    mont_mul(r1,x1,y1,w,n);
//    gmp_printf("r1 = %Zd\n", r1);
//    
//    mont_mul(r,r1,one,w,n);
//    gmp_printf("r = %Zd\n",r);
//    return;
//}
//
//
//void autoTest_mont()
//{
//    mpz_t p,q,n,rho2,x,y,x1,y1,r,r1,one,result;
//    mpz_inits(p,q,n,rho2,x,y,x1,y1,r,r1,one,result,NULL);
//    
//    mpz_set_ui(one,1);
//    gmp_scanf("%Zd %Zd",p,q);
//    mpz_mul(n,p,q);
//    get_rho2(rho2,n);
//    mp_limb_t w = get_omega(n);
//    
//    mpz_set_ui(x,2);
//    mpz_set_ui(y,2);
//    mpz_pow_ui(x,x,550);
//    mpz_pow_ui(y,y,550);
//    for (int k=1;k<10;k++)
//    {
//        printf("%d\n",k);
//        for (int i=1;i<10;i++)
//        {
//            
//            for (int j=1;j<10;j++)
//            {
//                mont_mul(x1,x,rho2,w,n);
//                mont_mul(y1,y,rho2,w,n);
//                mont_mul(r1,x1,y1,w,n);
//                mont_mul(r,r1,one,w,n);
//                
//                mpz_mul(result,x,y);
//                mpz_mod(result,result,n);
//                
//                if (mpz_cmp(r,result))
//                {
//                    printf("wrong\n");
//                }
//                //else
//                //    printf("1");
//                
//                mpz_add_ui(x,x,1);
//            }
//            mpz_add_ui(y,y,1);
//        }
//        mpz_mul_ui(n,n,1024);
//        mpz_add_ui(n,n,1);
//        get_rho2(rho2,n);
//        w = get_omega(n);
//    }
//}

/*
The main function acts as a driver for the assignment by simply invoking
the correct function for the requested stage.
*/
int main( int argc, char* argv[] ) {
    if( argc != 2 ) {
        abort();
    }

    if     ( !strcmp( argv[ 1 ], "stage1" ) ) {
        stage1();
    }
    else if( !strcmp( argv[ 1 ], "stage2" ) ) {
        stage2();
    }
    else if( !strcmp( argv[ 1 ], "stage3" ) ) {
        stage3();
    }
    else if( !strcmp( argv[ 1 ], "stage4" ) ) {
        stage4();
    }
    else {
        abort();
    }

    return 0;
}
