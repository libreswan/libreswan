# Convert random IDs such as a CKAID into symbolic names.  For
# instance:
#
#  CKAID: 123456  ->  CKAID: <<CKAID#1>>
#
# To debug, uncomment below then run script as:
#
#    awk -f id-sanitize east.console.verbose.txt 2>&1 > /dev/null
#

func debug(line) {
    # print "DEBUG:", line >> "/dev/stderr"
}

#
# Scan the line for new IDs using PATTERN.  Save them in VALUES table.
#
# PATTERN has the form "(NAME) ... (VALUE)"
#
func find(name, pattern,
	  n, fields, nr_fields, field, value) {
    # extract parts of the line matching pattern
    debug("find: pattern: " pattern)
    nr_fields = patsplit($0, fields, pattern)
    debug("find: nr_fields: " nr_fields)
    # go through each pattern that matches extracting PREFIX and ID
    for (n = 1; n <= nr_fields; n++) {
	field = fields[n]
	debug("find: fields[" n "]: " field)

	# extract value
	value = gensub(pattern, "\\1", 1, field)
	debug("find: name: " name " value: " value)

	# deal with regex characters and duplicates
	value = gensub(/([+/])/, "[\\1]", "g", value)
	if (value in values) {
	    debug("find: duplicate value")
	    continue
	}

	# add the new value to the values table.
	counts[name] += 1
	values[value] = sprintf("<<" name "#%x>>", counts[name])
	debug("find: value: " value " replacement: " values[value])
    }
}

{
    debug("INPUT: " $0)

    # Look for values, map each to a unique constant.
    find("CKAID", "CKAID ([0-9a-f]+)")
    find("CKAID", "CKAID '([0-9a-f]+)'")
    find("CKAID", "[^a-z]ckaid ([0-9a-f]+)")
    find("CKAID", "[^a-z]ckaid '([0-9a-f]+)'")
    find("CKAID", "ckaid: ([0-9a-f]+)")
    find("CKAID", "CKAID: ([0-9a-f]+)")
    # < 0> rsa      01de34c675160eb6aa7f74b6430d8637d75c4674   east
    find("CKAID", "< *[0-9]+> rsa *([+=0-9a-zA-Z/]+)")
    find("CKAID", "ckaid=([+=0-9a-zA-Z/]+)")

    find("RAW-PUBKEY", "rsasigkey=0s([+=0-9a-zA-Z/]+)")
    find("RAW-PUBKEY", "ecdsakey=0s([+=0-9a-zA-Z/]+)")
    find("RAW-PUBKEY", "eddsakey=0s([+=0-9a-zA-Z/]+)")
    find("PEM-PUBKEY", "pubkey=([+=0-9a-zA-Z/]+)")

    # RSA's algorithm is 2; ECDSA is 3; EDDSA is 4; 5 is made up
    find("RAW-PUBKEY", "IPSECKEY +[0-9]+ +[0-9]+ +[234] +[.:0-9a-f]+ +([+=0-9a-zA-Z/]+)$")
    find("PEM-PUBKEY", "IPSECKEY +[0-9]+ +[0-9]+ +[5] +[.:0-9a-f]+ +([+=0-9a-zA-Z/]+)$")

    find("KEYID", "keyid: ([+=0-9a-zA-Z/]+)")

    # replace all IDs with symbolic values
    old = $0
    for (value in values) {
	name = values[value]
	debug("value: " value)
	debug("name: " name)
	new = gensub("( |=0s|=)(" value ")([ ']|$)", "\\1" name "\\3", "g", old)
	debug("old: " old)
	debug("new: " new)
	old = new
    }

    print old
}
