#!/bin/sh

. ../../default-testparams.sh

# specific to nss tests
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS all-date-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS id-sanitize.awk"
