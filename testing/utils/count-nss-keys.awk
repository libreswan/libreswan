BEGIN {
    status = 0
}

func error(what) {
    print FILENAME ":" NR ": " what ": " $0
    status = 1
}

/: new .*-key@0x/ {
    key = gensub(/.*: new .*-(key@0x[^ ,]*).*/, "\\1", 1)
    if (!(key in counts)) {
	counts[key] = 1
    } else if (counts[key] == 0) {
	counts[key] = 1
    } else {
	error("new: key@" key " in use")
    }
    next
}
/: reference .*-key@0x/ {
    key = gensub(/.*: reference .*-(key@0x[^ ,]*).*/, "\\1", 1)
    if (!(key in counts)) {
	error("reference: key@" key " unknown")
    } else if (counts[key] == 0) {
	error("reference: key@" key " released")
    } else {
	counts[key]++
    }
    next
}
/: release .*-key@0x/ {
    key = gensub(/.*: release .*-(key@0x[^ ,]*).*/, "\\1", 1)
    if (!(key in counts)) {
	error("release: key@" key " unknown")
    } else if (counts[key] == 0) {
	error("release: key@" key " already released")
    } else {
	counts[key]--
    }
    next
}
END {
    for (key in counts) {
	if (counts[key]) {
	    print key, counts[key]
	    status = 1
	}
    }
    exit status
}
