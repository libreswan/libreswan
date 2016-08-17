func debug(line) {
    # print "DEBUG:", line >> "/dev/stderr"
}

# Pattern matches (prefix) ... (id)
func find(pattern,  n, fields, nr_fields, field, name, value) {
    debug("find: pattern: " pattern)
    nr_fields = patsplit($0, fields, pattern)
    debug("find: nr_fields: " nr_fields)
    for (n = 1; n <= nr_fields; n++) {
	field = fields[n]
	debug("find: fields[" n "]: " field)

	# extract name/value
	name = toupper(gensub(pattern, "\\1", 1, field))
	value = gensub(pattern, "\\2", 1, field)
	debug("find: name: " name " value: " value)

	# deal with regex characters and duplicates
	value = gensub(/([+/])/, "[\\1]", "g", value)
	if (value in values) {
	    debug("find: duplicate value")
	    continue
	}

	# add the new value
	counts[name] += 1
	values[value] = sprintf("<<" name "#%x>>", counts[name])
	debug("find: value: " value " replacement: " values[value])
    }
}

{
    debug("INPUT: " $0)

    # Look for name/values, map each to a unique constant.
    find("(CKAID) ([0-9a-f]+)")
    find("(CKAID) '([0-9a-f]+)'")
    find("(ckaid): ([0-9a-f]+)")
    find("(rsasigkey)=(0s[+=0-9a-zA-Z/]+)")
    find("(keyid): ([+=0-9a-zA-Z/]+)")
    find("(pubkey)=(0s[+=0-9a-zA-Z/]+)")

    old = $0
    for (value in values) {
	name = values[value]
	debug("value: " value)
	debug("name: " name)
	new = gensub("([ ='])(" value ")([ ']|$)", "\\1" name "\\3", "g", old)
	debug("old: " old)
	debug("new: " new)
	old = new
    }

    print old
}
