 CC        = g++
 CC_FLAGS  = -Wall -W -O3 -fopenmp
 CC_PATHS  = 
 CC_LIBS   =

# uncomment to use the default (probably older) OpenSSL installation
#CC_PATHS +=
#CC_LIBS  +=              -lcrypto
# uncomment to use the bespoke (probably newer) OpenSSL installation
 CC_PATHS += -I ~page/local/linux.x86_64/openssl-1.0.1m/include/
 CC_PATHS += -L ~page/local/linux.x86_64/openssl-1.0.1m/lib/
 CC_LIBS  += -Wl,-Bstatic -lcrypto -Wl,-Bdynamic

all: 
	@${CC} ${CC_FLAGS} ${CC_PATHS} attack.cpp -o attack ${CC_LIBS}