#updated by kobe, 2016.1.13
#---------------------------------------------------------------------------------------------
TARGET=cloudgate
BUILDVERSION=$(shell date +%Y%m%d)

CC=$(TOOLPREFIX)gcc
DEF=-DBUILDVERSION=$(BUILDVERSION) -DMYDEBUG
CFLAGS=-g -O2 -Wall -fno-strict-aliasing $(DEF)
INCPATH=-I/usr/include/ -I./
LDPATH=
LIBS=-lcurl
#---------------------------------------------------------------------------------------------

all: $(TARGET)

.SUFFIXES: .o .c .h
#---------------------------------------------------------------------------------------------

cloudgate: main.o config.o common.o md5.o mycurl.o cjson.o base64.o
	$(CC) $(CFLAGS) $(INCPATH) $(LDPATH) -o $@ $^ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCPATH) $(LDPATH) -c $<
#---------------------------------------------------------------------------------------------
clean:
	wc -l *.c *.h
	rm -rf $(TARGET) *.o *.so *.a *~

install:
	install -d $(INSTALL_ROOT)/usr/sbin/
	install $(TARGET) $(INSTALL_ROOT)/usr/sbin/
