#!/bin/sh

set -eu

# enum name checklist, for libreswan
#
# Copyright (C) 2023-2024  Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

names=$1 ; shift

list()
{
    # the special comment /* #ifdef MACRO */, at the end of a declaration is
    # used to flag that the declaration should be wrapped in #ifdef
    # MACRO.
    sed -n \
	-e "s/^extern ${names} \([a-z0-9_]*\);.* #ifdef \([A-Z0-9_]*\).*$/\1 \2/p" \
	-e "s/^extern ${names} \([a-z0-9_]*\);.*$/\1/p" \
	-e "s/^extern const struct ${names} \([a-z0-9_]*\);.* #ifdef \([A-Z0-9_]*\).*$/\1 \2/p" \
	-e "s/^extern const struct ${names} \([a-z0-9_]*\);.*$/\1/p" \
	"$@"
}

echo $(list "$@") 1>&2


cat <<EOF
/* enum name checklist, for libreswan
 *
 * Copyright (C) 2023-2024  Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */
EOF

echo
echo '#include "constants.h" /* for typedef ${names} */'
echo '#include "enum_names.h"'
echo

grep -e "^extern ${names} " -e "^extern const struct ${names} " "$@" | \
    cut -d: -f1 | \
    cut -d/ -f4- | \
    sort -u | \
    while read h ; do
	echo '#include "'${h}'"'
    done

echo

echo "const struct ${names}_check ${names}_checklist[] = {"
list "$@" | while read name ifdef ; do
    test -z "${ifdef}" || echo "#ifdef ${ifdef}"
    echo "  { \"${name}\", &${name}, },"
    test -z "${ifdef}" || echo "#endif"
done
echo "  { NULL, NULL, }"
echo "};"
