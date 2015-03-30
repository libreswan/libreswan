mk/tests.mk
-----------

This script goes through a whole heap of make commands, such as
sub-directory clean/build, that should work.

TODO list
---------

lib/libswan/Makefile use library.mk: it contains conditional
definitions so need to first come up with a simple general way to deal
with that.

enable -std=gnu99: hopefully just slog

eliminate Makefile.program

eliminate Makefile.manpage

OBJ.* include kernel and KVM

clean up the pluto directory some more

Free up CFLAGS, like autoconf/automake?

subdir.mk to a hard case

testing/pluto/Makefile update target

= vs := and overrides

Make --warn-undefined-variables

descend srcdir not objdir

eliminate Makefile.ver: this is really messy as scripts do all sorts
of wierd and wonderful stuff with it.

kvm-build-east use "make" and not "swan-build"

have swantest check exit status and bail when tests start to fail.
