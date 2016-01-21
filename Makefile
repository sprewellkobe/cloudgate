#updated by kobe, 2016.1.13
#---------------------------------------------------------------------------------------------
OUTPUTFILES=cloudgate
BUILDVERSION=$(shell date +%Y%m%d)
CFLAGS=-I/usr/include/ -I./ -L/usr/local/lib -DBUILDVERSION=$(BUILDVERSION) -DMYDEBUG
CC=gcc -g -Wall -fno-strict-aliasing
LIBS=-lcurl
#---------------------------------------------------------------------------------------------

all: $(OUTPUTFILES)

.SUFFIXES: .o .c .h
#---------------------------------------------------------------------------------------------

cloudgate: main.o config.o common.o md5.o mycurl.o cjson.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $<
#---------------------------------------------------------------------------------------------
clean:
	wc -l *.c *.h
	rm -rf $(OUTPUTFILES) *.o *.so *.a *~
