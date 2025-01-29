# reference counting checker, for libreswan
#
# Copyright (C) 2017,2019 Andrew Cagney
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

# Script for checking reference counted pointers; notably symkeys
# which libreswan doesn't directly manage.
#
# The script is looking for debug-log entries of the form:
#
#	[|:] newref .*@0xADDRESS[(NNN)].*
#	[|:] addref .*@0xADDRESS[(NNN)].*
#	[|:] delref .*@0xADDRESS[(NNN)].*
#
# and optionally:
#
#       [|:] freeref .*@0xADDRESS[(NNN)].*
#

BEGIN {
    status = 0
}

{
    key = ""
    count = -1
    op = ""
}

func debug(what) {
    if (DEBUG) {
	print $0 " DEBUG: " what
    }
}

func error(key, message) {
    print "ERROR: " op ": '" key "' " message
    if (key in history) {
	print history[key]
    }
    if (what) {
	print NR ": " $0 "\n"
    }
    status = 1
}

/@0x/ {
    key = gensub(/.*@(0x[0-9a-fA-F]*).*/, "\\1", 1)
    debug("key='" key "'")
}

/@0x[0-9a-fA-F]*\([0-9]*->[0-9]*\)/ {
    count = gensub(/.*@0x[0-9a-fA-F]*\([0-9]*->([0-9]*)\).*/, "\\1", 1)
    debug("count='" count "'")
}

/[|:] [a-z]*ref .*@0x/ {
    op = gensub(/.*[|:] ([a-z]*)ref .*/, "\\1", 1)
    debug("op='" op "'")
}

op == "new" {
    debug("new")
    if ((key in counts) && counts[key] != 0) {
	history[key] = history[key] "\n" NR ": " $0
	error(key, "already in use")
    } else {
	counts[key] = 1
	history[key] = NR ": " $0
	if (count >= 0 && count != counts[key]) {
	    error(key, "has wrong count " count "; expecting" counts[key])
	}
    }
    next
}

op == "add" {
    debug("add")
    if (!(key in counts)) {
	error(key, "unknown")
    } else {
	history[key] = history[key] "\n" NR ": " $0
	if (counts[key] == 0) {
	    error(key, "already released")
	} else {
	    counts[key]++
	}
	if (count >= 0 && count != counts[key]) {
	    error(key, "has wrong count")
	}
    }
    next
}

op == "del" {
    debug("del")
    if (!(key in counts)) {
	error(key, "unknown")
    } else {
	history[key] = history[key] "\n" NR ": " $0
	if (counts[key] == 0) {
	    error(key, "already released")
	} else {
	    counts[key]--
	}
	if (count >= 0 && count != counts[key]) {
	    error(key, "has wrong count")
	}
    }
    next
}

op == "free" {
    debug("free")
    if (!(key in counts)) {
	error(key, "unknown")
    } else {
	history[key] = history[key] "\n" NR ": " $0
	if (counts[key] != 0) {
	    error(key, "already released")
	}
	if (count >= 0 && count != counts[key]) {
	    error(key, "has wrong count")
	}
    }
    next
}

op == "peek" {
    debug("peek")
    if (!(key in counts)) {
	error(key, "unknown")
    } else {
	history[key] = history[key] "\n" NR ": " $0
	# gets by delete with 0 so checking is meaningless
    }
    next
}

op != "" {
    error(key, "operation unknown")
}

/@0x/ {
    op = "use"
    if (key in counts) {
	if (counts[key] == 0) {
	    history[key] = history[key] "\n" NR ": " $0
	    error(key, "use after free")
	}
    }
}

END {
    # this is in random order, oops
    op = ""
    for (key in counts) {
	if (counts[key]) {
	    error(key, "has count " counts[key])
	}
    }
    exit status
}
