#updated by kobe, 2016.1.13
#---------------------------------------------------------------------------------------------
#OS=`cat /etc/redhat-release | grep CentOS`
#TOOLPREFIX=$(shell if [[ -z "$(OS)" ]];then echo mips-linux-;else echo "";fi)
TARGET=cloudgate
TARGET_CONF=cloudgate.ini
NBSH_SYNC_CMD=nbsh_sycn_cmd.sh
BUILDVERSION=$(shell date +%Y%m%d)

CUN_DIR         = $(shell pwd)

ifneq "${TOOLPREFIX}" ""
BASE_DIR        = $(CUN_DIR)/../..
NBOS_SRC_DIR    = $(BASE_DIR)
APPS_DIR        = $(NBOS_SRC_DIR)/apps
UTIL_DIR        = $(APPS_DIR)/util
INCLUDE_PATH    = $(APPS_DIR)/include
LIBS_PATH       = $(APPS_DIR)/lib
AMU_PATH     	 = $(APPS_DIR)/amu
INCPATH         = -I$(INCLUDE_PATH) -I$(UTIL_DIR) -I$(AMU_PATH)/amu_lib
LDPATH          = -L$(LIBS_PATH)/curl -L$(LIBS_PATH)/openssl -L$(UTIL_DIR) -L$(AMU_PATH)/amu_lib
LIBS            += -lutil -lamu
DEF				 += -DBUILD_MIPS
else
INCPATH         = -I/usr/include/ -I./
endif
LIBS            += -lcurl -lcrypto -lssl

#---------------------------------------------------------------------------------------------
CC=$(TOOLPREFIX)gcc
DEF+=-DBUILDVERSION=$(BUILDVERSION) -DMYDEBUG
CFLAGS=-g -O2 -Wall -fno-strict-aliasing $(DEF)
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
	install $(NBSH_SYNC_CMD) $(INSTALL_ROOT)/usr/local/sbin/
	install $(TARGET_CONF) $(INSTALL_ROOT)/etc/default/
	
