#!/bin/sh

# running under a namespace?
# BETTER? expr "$SUDO_COMMAND" : ".*/nsenter " > /dev/null
if echo $SUDO_COMMAND | grep "/bin/nsenter " > /dev/null 2>&1 ; then
    if "$@" > OUTPUT/if-namespace.$$.log 2>&1 ; then
	echo === cut ===
	cat OUTPUT/if-namespace.$$.log
	echo === tuc ===
    else
	cat OUTPUT/if-namespace.$$.log
    fi
else
    : be happy
fi
