#!/bin/sh -e

# Find anything remotely related to makefiles; used to find makefile
# variable references.  Assume this is being run as .../mk/find.sh.

look()
{
    d=$(dirname $(dirname $0))
    find $d/* \
         -name 'BACKUP' -prune \
	 -o -name 'OUTPUT' -prune \
	 -o -name '__pycache__' -prune \
	 -o -name '*~' -prune \
	 -o -name '*.orig' -prune \
	 -o -name '*.rej' -prune \
	 -o -name '.*' -prune \
	 \
	 -o         -path "$d/OBJ.*" -prune \
	 -o         -path "$d/linux" -prune \
	 -o         -path "$d/testing/pluto/*/*" -prune \
	 -o -type f -path "$d/testing/utils/*" -print \
	 -o -type f -path "$d/testing/guestbin/*" -print \
	 \
	 -o -type f -path "$d/packaging/*" -print \
	 \
	 -o -type f -name 'Makefile*' -print \
	 -o -type f -name '*.mk' -print \
	 -o -type f -name '*.py' -print \
	 -o -type f -name '*.sh' -print \
	 -o -type f -name '*.awk' -print \
	 -o -type f -name '*.[chly]' -print
}

if test $# -gt 0 ; then
    look | xargs grep -n "$@"
else
    look
fi
