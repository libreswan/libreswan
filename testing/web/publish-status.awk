#!/bin/awk

BEGIN {
    if (!script) {
	script = "echo script:"
	debug = 1
    }
}

{ if (!debug) print }

# b1.runner psk-pluto-05 4:29.04: start processing test psk-pluto-05 (test 5 of 5) at 2016-09-20 10:40:36.929240
/: start processing test / {
    # need to convert the localtime date to ISO format
    date = gensub(/.* at /, "", 1, $0)
    "date -Iseconds -d '" date "'" | getline date
    test = gensub(/.* processing test ([^ ]*) .*/, "\\1", 1, $0)
    count = gensub(/.* \((test [0-9]* of [0-9]*)\) .*/, "\\1", 1, $0)
    details = "(processing " test ", " count ")"
    if (debug) print "date=" date, "details=" details >> "/dev/stderr"
    # While updates are not very atomic they are good enough for now
    # and allow json=/dev/stderr for testing.
    system(script " --date '" date "' '" details "'")
}
