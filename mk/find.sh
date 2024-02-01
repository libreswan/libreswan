#!/bin/sh -e

# Find anything remotely related to makefiles; used to find makefile
# variable references.  Assume this is being run as .../mk/find.sh.

look()
{
    d=$(dirname $(dirname $0))
    find $d/* \
	 -false \
	 -o -type d -name '__pycache__' -prune \
	 \
	 -o -type f -name '*~' -prune \
	 -o -type f -name '*.orig' -prune \
	 -o -type f -name '*.rej' -prune \
	 -o -type f -name '.*' -prune \
	 \
         -o -type d -path '$d/BACKUP' -prune \
	 -o -type d -path "$d/OBJ.*" -prune \
	 -o -type d -path "$d/linux" -prune \
	 -o -type d -path "$d/contrib" -prune \
	 -o -type d -path "$d/testing/pluto/*/*" -prune \
	 \
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
	 -o -type f -name '*.in' -print \
	 -o -type f -name '*.[chly]' -print \
	 -o -type f -name '*.lex' -print
	 -o -type f -name '*.xml' -print
}

if test $# -gt 0 ; then
    look | xargs grep -n "$@"
else
    look
fi
