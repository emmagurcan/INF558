CC = gcc

CFLAGS = -std=c99 -Wall -Wwrite-strings -g

OBJS=utilities.o buffer.o random.o hashtable.o bits.o base64.o

LIB=inf558_tools.a

$(LIB): $(OBJS)
	-rm -f $(LIB)
	ar cr $(LIB) $(OBJS)
	ranlib $(LIB)

utilities.o: utilities.c utilities.h
	$(CC) $(CFLAGS) -c utilities.c

buffer.o: buffer.c buffer.h
	$(CC) $(CFLAGS) -c buffer.c

random.o: random.c random.h
	$(CC) $(CFLAGS) -c random.c

hashtable.o: hashtable.c hashtable.h
	$(CC) $(CFLAGS) -c hashtable.c

bits.o: bits.c bits.h
	$(CC) $(CFLAGS) -c bits.c

base64.o: base64.c base64.h
	$(CC) $(CFLAGS) -c base64.c

clean:
	rm -f *.o $(LIB)
