## Process this file with automake to produce Makefile.in

APPNAME = seafile-applet

TARGET = $(APPNAME).exe

all: $(TARGET)
en: $(TARGET)

top_srcdir=../..

GLIB_CFLAGS=$(shell pkg-config --cflags libsearpc)
GLIB_LDFLAGS=$(shell pkg-config --libs libsearpc)

CFLAGS += -I$(top_srcdir)/include \
		-I$(top_srcdir)/lib \
		-I$(top_srcdir)/common \
		-I. -I../common \
        $(GLIB_CFLAGS) -g -O0 -Wall

LDFLAGS += -L${top_srcdir}/lib/.libs/   \
	-lseafile -lseafile_common -lccnet\
	-lcrypto -lgdi32 -levent  \
	-lRpcrt4 -lpthread -lws2_32 -lpsapi -lshlwapi \
	$(GLIB_LDFLAGS)

CC = gcc
RC = windres
ICONS = seafile.ico ccnet_daemon_up.ico ccnet_daemon_down.ico \
	seafile_transfer_1.ico seafile_transfer_2.ico \
	seafile_transfer_3.ico seafile_transfer_4.ico \
	seafile_auto_sync_disabled.ico \
	window-head.bmp \

CFLAGS += -DWINVER=0x500 -D_WIN32_IE=0x500
LDFLAGS += -lcomctl32 -lcomdlg32

ifeq (${MAKECMDGOALS}, en)
	# CFLAGS += -DSEAF_LANG_ENGLISH
	RCFILE = trayicon.en.rc
	RC_HEADER = resource.en.h
else
	# CFLAGS += -DSEAF_LANG_CHINESE
	RCFILE = trayicon.rc
	RC_HEADER = resource.h
endif

ifeq (${MAKECMDGOALS}, debug)
	CFLAGS += -g -O0 -D _DEBUG
	LDFLAGS += -Wl,--subsystem,console
else
	LDFLAGS += -Wl,--subsystem,windows
endif

SRCS = seafile-applet.c trayicon.c init-ccnet.c

COMMON_SRCS = \
	../common/opendir-proc.c ../common/ccnet-init.c \
	../common/applet-log.c ../common/rpc-wrapper.c \
	../common/applet-common.c ../common/applet-rpc-service.c

OBJECTS = ${SRCS:%.c=%.o}  ${COMMON_SRCS:../common/%.c=%.o}

.deps: $(SRCS) $(COMMON_SRCS)
	@echo generating dependency ...
	$(CC) $(CFLAGS) -MM $^ > $@

-include .deps

applet-common.o : ../common/applet-common.c
	$(CC) $(CFLAGS) -c $< -o $@

applet-rpc-service.o : ../common/applet-rpc-service.c
	$(CC) $(CFLAGS) -c $< -o $@

opendir-proc.o : ../common/opendir-proc.c
	$(CC) $(CFLAGS) -c $< -o $@

ccnet-init.o : ../common/ccnet-init.c
	$(CC) $(CFLAGS) -c $< -o $@

applet-log.o : ../common/applet-log.c
	$(CC) $(CFLAGS) -c $< -o $@

rpc-wrapper.o : ../common/rpc-wrapper.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : %.c
	${CC} ${CFLAGS} -c $< -o $@

resource.o : ${RCFILE} ${RC_HEADER} ${ICONS} Application.manifest
	${RC}  -i $< -o $@

$(TARGET) : $(OBJECTS) resource.o .deps
	${CC} -o "$@" ${OBJECTS} resource.o ${LDFLAGS} 

debug:all
distclean:clean
dist:
distdir:
install:
uninstall:

clean :
	rm -f *.o *.exe .deps

.PHONY: all en debug clean dist distclean install uninstall 
