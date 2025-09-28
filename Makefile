# to use me you have to specify make -f Makefile

main : main.o peer.o
	gcc -g $^ -o $@ -I/usr/include/openssl -L/usr/lib -lcrypto -lssl

%.o : %.c
	gcc -g -c $<

clean :
	rm -f *.o main .depend
.PHONY: clean

.depend: main.c peer.c
	gcc -MM $^ > .depend
include .depend
