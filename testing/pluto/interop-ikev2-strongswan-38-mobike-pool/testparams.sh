#!/bin/sh

. ../../default-testparams.sh
ROAD_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS strongswan.sed"
ROAD_CONSOLE_FIXUPS="$ROAD_CONSOLE_FIXUPS ip-xfrm.sed"
EAST_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ip-xfrm.sed"
