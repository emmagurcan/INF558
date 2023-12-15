LIBPATH = ..
include $(LIBPATH)/Lib/Makefile.common

all: test_certificate handle_certificate client server eol gen

clean:
	rm -f *.o test_certificate handle_certificate client server \
	eol key_gen testAES
	make -f MakefileGen clean

cleanall: clean
	make -f MakefileGen cleanall
	rm -f port.txt
	rm -rf .cache
	rm -f core

######################################################################

OBJS = sign.o rsa.o

test_aes.o: test_aes.c
	$(CC) $(CFLAGS) -c test_aes.c -o ./test_aes.o

test_aes: test_aes.o 
	$(CC) $(LDFLAGS) test_aes.o $(LIBS) -o ./test_aes	

rsa.o: rsa.c rsa.h
	$(CC) $(CFLAGS) -c rsa.c -o ./rsa.o

sign.o: sign.c sign.h
	$(CC) $(CFLAGS) -c sign.c -o ./sign.o

certificate.o: certificate.c certificate.h
	$(CC) $(CFLAGS) -c certificate.c -o ./certificate.o

test_certificate.o: test_certificate.c
	$(CC) $(CFLAGS) -c test_certificate.c -o ./test_certificate.o

test_certificate: certificate.o test_certificate.o sign.o rsa.o
	$(CC) $(LDFLAGS) certificate.o test_certificate.o sign.o rsa.o \
	      $(LIBS) -o ./test_certificate

handle_certificate.o: handle_certificate.c
	$(CC) $(CFLAGS) -c handle_certificate.c -o ./handle_certificate.o

handle_certificate: certificate.o handle_certificate.o $(OBJS)
	$(CC) $(LDFLAGS) certificate.o handle_certificate.o \
	$(OBJS) $(LIBS) -o ./handle_certificate

NET_OBJS = dh.o channel.o network.o certificate.o $(OBJS)
network.o: network.c network.h
	$(CC) $(CFLAGS) -c network.c -o ./network.o

channel.o: channel.c channel.h
	$(CC) $(CFLAGS) -c channel.c -o ./channel.o

dh.o: dh.c dh.h
	$(CC) $(CFLAGS) -c dh.c -o ./dh.o

client_aux.o: client_aux.c client.h
	$(CC) $(CFLAGS) -c client_aux.c -o ./client_aux.o

client: client_aux.o client.c $(NET_OBJS)
	$(CC) $(CFLAGS) client.c client_aux.o $(NET_OBJS) $(LIBS) -o ./client

server: server.c $(NET_OBJS)
	$(CC) $(CFLAGS) server.c $(NET_OBJS) $(LIBS) -o ./server

eol: eol.c
	$(CC) $(CFLAGS) eol.c -o ./eol

gen:
	make -f MakefileGen

