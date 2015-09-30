# makefile for netcat, based off same ol' "generic makefile".
# Usually do "make systype" -- if your systype isn't defined, try "generic"
# or something else that most closely matches, see where it goes wrong, fix
# it, and MAIL THE DIFFS back to Hobbit.

### PREDEFINES

# DEFAULTS, possibly overridden by <systype> recursive call:
# pick gcc if you'd rather , and/or do -g instead of -O if debugging
# debugging
# DFLAGS = -DTEST
CFLAGS = -O
XFLAGS = 	# xtra cflags, set by systype targets
XLIBS =		# xtra libs if necessary?
# -Bstatic for sunos,  -static for gcc, etc.  You want this, trust me.
STATIC =
CC = gcc $(CFLAGS)
LD = $(CC)	# linker; defaults to unstripped executables
o = o		# object extension

ALL = nc

-include Makefile.local

### BOGON-CATCHERS

bogus:
	@echo "Usage:  make  <systype>  [options]"

### HARD TARGETS

nc:	netcat.c
	$(LD) $(DFLAGS) $(XFLAGS) $(STATIC) -o nc netcat.c $(XLIBS)

nc-dos:
	@echo "DOS?!  Maybe someday, but not now"

### SYSTYPES -- in the same order as in generic.h, please

# designed for msc and nmake, but easy to change for your compiler.
# Recursive make may fail if you're short on memory -- u-fix!
# Note special hard-target and "quotes" instead of 'quotes' ...
dos:
	$(MAKE) -e $(ALL)-dos $(MFLAGS) CC="cl /nologo" XLIBS= \
	XFLAGS="/AS -D__MSDOS__ -DMSDOS"  o=obj

ultrix:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DULTRIX'

# you may need XLIBS='-lresolv -l44bsd' if you have BIND 4.9.x
sunos:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DSUNOS' STATIC=-Bstatic \
	XLIBS='-lresolv'

# Pick this one ahead of "solaris" if you actually have the nonshared
# libraries [lib*.a] on your machine.  By default, the Sun twits don't ship
# or install them, forcing you to use shared libs for any network apps.
# Kludged for gcc, which many regard as the only thing available.
solaris-static:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DSYSV=4 -D__svr4__ -DSOLARIS' \
	CC=gcc STATIC=-static XLIBS='-lnsl -lsocket -lresolv'

# the more usual shared-lib version...
solaris:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DSYSV=4 -D__svr4__ -DSOLARIS' \
	CC=gcc STATIC= XLIBS='-lnsl -lsocket -lresolv'

aix:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DAIX'

linux:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DLINUX' STATIC=-static

# irix 5.2, dunno 'bout earlier versions.  If STATIC='-non_shared' doesn't
# work for you, null it out and yell at SGI for their STUPID default
# of apparently not installing /usr/lib/nonshared/*.  Sheesh.
irix:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DIRIX -DSYSV=4 -D__svr4__' \
	STATIC=-non_shared

osf:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DOSF' STATIC=-non_shared

# virtually the same as netbsd/bsd44lite/whatever
freebsd:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DFREEBSD' STATIC=-static

bsdi:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DBSDI' STATIC=-Bstatic

netbsd:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DNETBSD' STATIC=-static

# finally got to an hpux box, which turns out to be *really* warped.
# STATIC here means "linker subprocess gets args '-a archive'" which causes
# /lib/libc.a to be searched ahead of '-a shared', or /lib/libc.sl.
hpux:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DHPUX' STATIC="-Wl,-a,archive"

# unixware from bmc@telebase.com; apparently no static because of the
# same idiotic lack of link libraries
unixware:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DUNIXWARE -DSYSV=4 -D__svr4__' \
	STATIC= XLIBS='-L/usr/lib -lnsl -lsocket -lresolv'

# from Declan Rieb at sandia, for a/ux 3.1.1 [also suggests using gcc]:
aux:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DAUX' STATIC=-static CC=gcc

# Nexstep from mudge: NeXT cc is really old gcc
next:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DNEXT' STATIC=-Bstatic

# start with this for a new architecture, and see what breaks.
generic:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DGENERIC' STATIC=

# Still at large: dgux dynix ???

### RANDOM

clean:
	rm -f $(ALL) *.o *.obj

