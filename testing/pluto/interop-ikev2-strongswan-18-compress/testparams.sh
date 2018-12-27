#!/bin/sh

. ../../default-testparams.sh
EAST_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS strongswan.sed ip-xfrm-compress.sed"
WEST_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ip-xfrm-compress.sed"
