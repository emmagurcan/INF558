LIBPATH = ..
include $(LIBPATH)/Lib/Makefile.common

all: test_lab7

clean:
	rm -f *.o test_lab7

cleankeys:
	rm -f DSA_pub.txt DSA_sec.txt Declaration_dh_DSA_signature.txt Duck_salad_RSA_signature.txt RSA_pub.txt RSA_sec.txt

cleanall: clean cleankeys

######################################################################
OBJS = rsa.o sign.o dsa.o attack_dsa.o

rsa.o: rsa.c rsa.h
	$(CC) $(CFLAGS) -c rsa.c -o ./rsa.o

sign.o: sign.c sign.h
	$(CC) $(CFLAGS) -c sign.c -o ./sign.o

dsa.o: dsa.c dsa.h
	$(CC) $(CFLAGS) -c dsa.c -o ./dsa.o

attack_dsa.o: attack_dsa.c attack_dsa.h
	$(CC) $(CFLAGS) -c attack_dsa.c -o ./attack_dsa.o


test_lab7: test_lab7.c $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) test_lab7.c $(OBJS) $(LIBS) -o ./test_lab7

test_lab7s:
	for i in 1 2 3 4 5 6 7 8 9 10 11; do ./test_lab7 $$i; done
