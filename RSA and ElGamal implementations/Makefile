 CC        = /usr/bin/gcc
 CC_FLAGS  = -Wall -std=gnu99 -m64 -O3 
 CC_PATHS  = 
 CC_LIBS   =

# uncomment to use the older, default GMP installation
#CC_PATHS +=
#CC_LIBS  +=              -lgmp

# uncomment to use the newer, bespoke GMP installation
 CC_PATHS += -I/usr/local/gmp505/include/ 
 CC_PATHS += -L/usr/local/gmp505/lib/
 CC_LIBS  += -Wl,-Bstatic -lgmp -Wl,-Bdynamic

all    : modmul

modmul : $(wildcard *.[ch])
	@${CC} ${CC_FLAGS} ${CC_PATHS} -o ${@} $(filter %.c, ${^}) ${CC_LIBS}

clean  : 
	@rm -f core modmul
    
val1  :
	valgrind ./modmul stage1 < stage1.input > out.txt
	diff out.txt stage1.output
    
val2  :
	valgrind ./modmul stage2 < stage2.input > out.txt
	diff out.txt stage2.output
    
val3  :
	valgrind ./modmul stage3 < stage3.input > out.txt
    
val4  :
	valgrind ./modmul stage4 < stage4.input > out.txt
	diff out.txt stage4.output
    
stage1  :
	./modmul stage1 < stage1.input > out.txt
	diff out.txt stage1.output
    
stage2  :
	./modmul stage2 < stage2.input > out.txt
	diff out.txt stage2.output
    
stage3  :
	./modmul stage3 < stage3.input > out.txt
	diff out.txt stage3.output
    
stage4  :
	./modmul stage4 < stage4.input > out.txt
	diff out.txt stage4.output    

    
vrfy  : stage1 stage2 stage3 stage4