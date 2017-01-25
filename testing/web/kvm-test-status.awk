#!/bin/awk

BEGIN {
    if (!script) {
	script = "echo script:"
	debug = 1
    }
}

function status(message,  date, command) {
    # current time in ISO format
    date = strftime("%FT%TZ", systime(), 1)
    if (debug) print("date:", date)

    command = script " --date " date " ' (" message ")'"
    if (debug) {
	print("command:", command)
    } else {
	system(command)
    }
}

function extract(field, pattern,  result) {
    result = gensub(pattern, "\\1", 1, $0)
    if (result == $0) result = field "-error"
    if (debug) print(field ":", result)
    return result
}

{ if (!debug) print }

# b1.runner psk-pluto-05 4:29.04: start processing test psk-pluto-05 (test 5 of 5) at 2016-09-20 10:40:36.929240

/: start processing test / {

    test = extract("test", ".* processing test ([-a-z0-9]*) .*")
    count = extract("count", ".* \\((test [0-9]* of [0-9]*)\\) .*")

    status("processing " test ", " count)
}
