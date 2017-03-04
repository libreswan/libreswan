BEGIN {
    status = 0
}

func error(what) {
    print FILENAME ":" NR ": " what ": " $0
    status = 1
}

/: new .*-[a-z]*@0x/ {
    key = gensub(/.*: new .*-([a-z]*@0x[^ ,]*).*/, "\\1", 1)
    filename[key] = FILENAME
    nr[key] = NR
    line[key] = $0
    if (!(key in counts)) {
	counts[key] = 1
    } else if (counts[key] == 0) {
	counts[key] = 1
    } else {
	error("new: " key " in use")
    }
    next
}

/: reference .*-[a-z]*@0x/ {
    key = gensub(/.*: reference .*-([a-z]*@0x[^ ,]*).*/, "\\1", 1)
    if (!(key in counts)) {
	error("reference: " key " unknown")
    } else if (counts[key] == 0) {
	error("reference: " key " released")
    } else {
	counts[key]++
    }
    next
}

/: release .*-[a-z]*@0x/ {
    key = gensub(/.*: release .*-([a-z]*@0x[^ ,]*).*/, "\\1", 1)
    if (!(key in counts)) {
	error("release: " key " unknown")
    } else if (counts[key] == 0) {
	error("release: " key " already released")
    } else {
	counts[key]--
    }
    next
}
END {
    for (key in counts) {
	if (counts[key]) {
	    print filename[key] ":" nr[key] ": " key " " counts[key] ":: " line[key]
	    status = 1
	}
    }
    exit status
}
