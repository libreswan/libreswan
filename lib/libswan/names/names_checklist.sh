#!/bin/sh

set -eu

includedir=$(realpath $1) ; shift

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

# generate a list of declarations
#
# NAME: name of the names/sparse/enum being declared declaration
# KIND: is it names, enum_names, or sparse_names structure?
# HEADER: header it was found in
# [IFDEF]: Name of macro that declaration is dependent on

list()
{
    # The special comment /* #ifdef MACRO */, at the end of a
    # declaration is used to flag that the declaration should be
    # wrapped in #ifdef MACRO.  Just the macro name is included.
    {
	for h in "$@" ; do
	    header=$(realpath $h | sed -e 's;'${includedir}'/*;;')
	    sed -n \
		-e 's;^extern const struct \(names\) \([a-z0-9_]*\)\;.* #ifdef \([A-Za-z0-9_]*\).*$;\2 \1 '${header}' \3;p' \
		-e 's;^extern const struct \([a-z]*\)_names \([a-z0-9_]*\)\;.* #ifdef \([A-Za-z0-9_]*\).*$;\2 \1 '${header}' \3;p' \
		-e 's;^extern const struct \(names\) \([a-z0-9_]*\)\;.*$;\2 \1 '${header}';p' \
		-e 's;^extern const struct \([a-z]*\)_names \([a-z0-9_]*\)\;.*$;\2 \1 '${header}';p' \
		$h
	done
    } | {
	sort
    }
}

list "$@" 1>&2

println()
{
    printf "$@"
    printf '\n'
}

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

println ''
cat <<EOF
#include "names.h"
#include "enum_names.h"
EOF
println ''

# Generate a list of #includes so all declarations are visible.
#
# When a header contains multiple declarations with and without
# #ifdef, multiple #includes will be generated, some wrapped in
# #ifdef.  Oops.

list "$@" | cut '-d ' -f3- | sort -u | while read header ifdef ; do
    test -z "${ifdef}" || println '#ifdef '${ifdef}''
    println '#include "'${header}'"'
    test -z "${ifdef}" || println '#endif'
done

# For sparse_names and enum_names, generate names object wrappers.

list "$@" | while read name kind header ifdef ; do
    case ${kind} in
	enum | sparse )
	    println ''
	    test -z "${ifdef}" || println '#ifdef '${ifdef}''
	    println 'static const struct names '${name}'_'${kind}' = {'
	    println '\t.'${kind}'_names = &'${name}','
	    println '};'
	    test -z "${ifdef}" || println '#endif'
	    ;;
    esac
done

# generate the structure proper

println ''
println 'static const struct names_check names_check[] = {'
list "$@" | while read name kind header ifdef ; do
    test -z "${ifdef}" || println '#ifdef '${ifdef}''
    println '\t{'
    println '\t\t.kind = "'${kind}'",'
    println '\t\t.name = "'${name}'",'
    case ${kind} in
	enum | sparse )
	    println '\t\t.names = &'${name}'_'${kind}','
	    ;;
	names )
	    println '\t\t.names = &'${name}','
	    ;;
    esac
    println '\t},'
    test -z "${ifdef}" || println '#endif'
done
println '};'

println ''
println 'const struct names_checklist names_checklist = {'
println '\tARRAY_PTR(names_check),'
println '};'
