# Simple makefile to build the WEPATTACK Version 1.0
# 15-10-2002 Dominik Blunk and Alain Girardet
#
#
CC=gcc
LD=gcc
#
# CFLAGS
CFLAGS=-fno-for-scope -c -D__LINUX_WLAN__ -D__I386__
#
#
# LDFLAGS
#LDFLAGS=
#
#
# Libraries to link against
LIBS= -lpcap -lz -lcrypto
#
#
# Install path for wepattack
INSTDIR=/usr/bin

wepattack: 	wepattack.o rc4.o wepfilter.o log.o modes.o misc.o verify.o keygen.o
	$(LD) $(LDFLAGS) -o $@ wepattack.o rc4.o wepfilter.o log.o \
	modes.o misc.o verify.o keygen.o $(LIBS)

wepattack.o:	wepattack.c wepattack.h
	$(CC) $(CFLAGS) -o $@ wepattack.c

rc4.o:		rc4.c rc4.h
	$(CC) $(CFLAGS) -o $@ rc4.c

wepfilter.o:	wepfilter.c wepfilter.h
	$(CC) $(CFLAGS) -o $@ wepfilter.c

verify.o:	verify.c verify.h
	$(CC) $(CFLAGS) -o $@ verify.c

log.o:		log.c log.h
	$(CC) $(CFLAGS) -o $@ log.c

#nwepgen.o:	nwepgen.c nwepgen.h
#	$(CC) $(CFLAGS) -o $@ nwepgen.c

keygen.o:	keygen.c keygen.h
	$(CC) $(CFLAGS) -o $@ keygen.c

modes.o:	modes.c modes.h
	$(CC) $(CFLAGS) -o $@ modes.c

misc.o:		misc.c misc.h
	$(CC) $(CFLAGS) -o $@ misc.c

clean:
	rm -f *.o

purge:
	rm -f *.o
	rm -f wepattack

install:
	install -m 755 wepattack $(INSTDIR)
	install -m 755 ../run/wepattack_word $(INSTDIR)
	install -m 755 ../run/wepattack_inc $(INSTDIR)
	@if test -f /etc/wepattack.conf ; then \
		echo "/etc/wepattack.conf already exists..."; \
	else echo "creating /etc/wepattack.conf..."; \
		install -m 644 ../conf/wepattack.conf /etc ; fi

