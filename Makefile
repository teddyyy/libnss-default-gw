# Makefile for libnss-default-gw

CC = gcc
prefix = /usr
exec_prefix = ${prefix}
BITSOFS=
libprefix = ${exec_prefix}/lib$(BITSOFS)
DESTDIR=
OBJSUFFIX=$(BITSOFS).o
OBJECTS=libnss_default_gw$(OBJSUFFIX)
SHARED_OBJECT = libnss_default_gw$(BITSOFS).so.2
INSTALL_NAME = libnss_default_gw.so.2
# This only works sometimes, give manually when needed:
BIT_CFLAGS = $(if $(BITSOFS),-m$(BITSOFS))
CFLAGS = $(BIT_CFLAGS) -g -O2 -Wall -Wpointer-arith
CPPFLAGS =
LIBS = -lnl-3 -lnl-route-3
LDFLAGS = -shared -Wl,-soname,$(INSTALL_NAME) -Wl,-z,defs
INCPATH = /usr/include/libnl3/

all: $(SHARED_OBJECT)

$(SHARED_OBJECT): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(SHARED_OBJECT) $(OBJECTS) $(LIBS)

%$(OBJSUFFIX): %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(INCPATH) -fPIC -c -o $@ $<

install:
	install -m755 -d $(DESTDIR)$(libprefix)/
	install -m644 $(SHARED_OBJECT) $(DESTDIR)$(libprefix)/$(INSTALL_NAME)

clean:
	rm -f $(OBJECTS)
	rm -f $(SHARED_OBJECT)

distclean: clean

.PHONY: all
