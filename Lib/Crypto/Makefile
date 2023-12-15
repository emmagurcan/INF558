CC = gcc

TOOLDIR = ../Tools
INCPATH = -I$(TOOLDIR)
TOOLS = $(TOOLDIR)/inf558_tools.a

CFLAGS = -std=c99 -Wall -Wwrite-strings -g $(INCPATH)

OBJS=aes.o sha3.o operating_modes.o

LIB=inf558_crypto.a

$(LIB): $(OBJS)
	-rm -f $(LIB)
	ar cr $(LIB) $(OBJS)
	ranlib $(LIB)

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) -c aes.c

sha3.o: sha3.c sha3.h
	$(CC) $(CFLAGS) -c sha3.c

operating_modes.o: operating_modes.c operating_modes.h
	$(CC) $(CFLAGS) -c operating_modes.c

clean:
	rm -f *.o inf558_crypto.a
