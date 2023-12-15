LIBPATH = ..
include $(LIBPATH)/Lib/Makefile.common

all: test_lab6

clean:
	rm -f *.o test_lab6

######################################################################

OBJS = rsa.o text_rsa.o xgcd.o crt.o hastad.o

xgcd.o: xgcd.c xgcd.h
	$(CC) $(CFLAGS) -c xgcd.c -o ./xgcd.o

crt.o: crt.c crt.h
	$(CC) $(CFLAGS) -c crt.c -o ./crt.o

rsa.o: rsa.c rsa.h
	$(CC) $(CFLAGS) -c rsa.c -o ./rsa.o

text_rsa.o: text_rsa.c text_rsa.h
	$(CC) $(CFLAGS) -c text_rsa.c -o ./text_rsa.o

hastad.o: hastad.c hastad.h
	$(CC) $(CFLAGS) -c hastad.c -o ./hastad.o


test_lab6.o: test_lab6.c
	$(CC) $(CFLAGS) -c test_lab6.c -o ./test_lab6.o

test_lab6: test_lab6.o $(OBJS)
	$(CC) $(LDFLAGS) test_lab6.o $(OBJS) $(LIBS) -o ./test_lab6
