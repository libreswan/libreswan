#!/bin/sh

# enum name checklist, for libreswan
#
# Copyright (C) 2023  Andrew Cagney
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
    sed -n \
	-e 's/^extern enum_names \([a-z0-9_]*\);.*$/\1/p' \
	-e 's/^extern const struct enum_names \([a-z0-9_]*\);.*$/\1/p' \
	"$@"
}

echo $(list "$@") 1>&2


cat <<EOF
/* enum name checklist, for libreswan
 *
 * Copyright (C) 2023  Andrew Cagney
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

cat <<EOF
#include "enum_names.h"
EOF

list "$@" | while read name ifdef ; do
    echo "extern struct ${names} ${name};"
done

echo "const struct ${names} *${names}_checklist[] = {"
list "$@" | while read name ifdef ; do
    echo "  &${name},"
done
echo "  NULL,"
echo "};"
