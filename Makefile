BIN=sandbox.cgi
OBJ=sandbox.o \
    filter.o

setcap:
	sudo setcap cap_sys_chroot+ep sandbox.cgi
include mk/c.mk
include config.mk
