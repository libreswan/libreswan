#!/bin/awk

BEGIN {
    if (!script) {
	script = "echo script:"
	debug = 1
    }
}

function status(message,  date, command) {
    command = script " '" message "'"
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

# .../kvmsh.py  --chdir . gh1.east 'export OBJDIR=OBJ.kvm ; make -j2 OBJDIR=OBJ.kvm base'

/kvmsh.py .* make / {

    domain = extract("domain", ".* ([-.a-z0-9]*(east|west|north|nic|road)) .*")
    target = extract("target", ".* ([-a-z]*)'$")

    # careful with quoting
    status("running \"make " target "\" on " domain)
}

# kvmsh.py  --chdir . --shutdown gh1.north 'export OBJDIR=OBJ.kvm ; ./testing/guestbin/swan-install OBJDIR=OBJ.kvm'

/kvmsh.py .*swan-install / {

    domain = extract("domain", ".* ([-.a-z0-9]*(east|west|north|nic|road)) .*")

    # careful with quoting
    status("running \"swan-install\" on " domain)
}
