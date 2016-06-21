BEGIN {
    debug = 0
}

func genid(prefix, id, trunc,  n, i) {
    counts[prefix] += 1
    # Make unique and truncate to a predictable length
    n = sprintf("<<" prefix "%x...>>", counts[prefix])
    # deal with regex characters in ID
    i = gensub(/([+/])/, "[\\1]", "g", id)
    if (debug) print "genid", "prefix:", prefix, "id:", id, "i:", i, "n:", n
    ids[i] = n
    # return the mangled ID - passed through to subid().
    return i
}

func subid(id,  new) {
    old = $0
    new = gensub("([ ='])(" id ")([ ']|$)", "\\1" ids[id] "\\3", "g", old)
    if (debug) print "subid", "id:", id, "old:", old, "new:", new
    if (old == new) return 0
    $0 = new
    return 1
}

{
    # Replace any IDs with unique but predictable values.
    for (id in ids) {
	subid(id)
    }

    # Look for new CKAIDs - map each to a unique constant.
    while (1) {
	# Above should have filtered out existing IDs; look for new
	# ones.
	id = gensub(/^.*(CKAID|ckaid:) +[']?([0-9a-f]+)([ '].*|)$/, "\\2", 1, $0)
	if (id == $0) break
	# convert to CKAID-xxxxxxx", the "-" stops re-matches
	if (!subid(genid("CKAID-", id))) break;
    }

    # Look for RSASIGKEYs - map each to something unique
    while (1) {
	# Above should have filtered out existing IDs; look for new
	# ones.
	id = gensub(/^.*(rsasigkey=)(0s[+=0-9a-zA-Z/]+)( .*|)$/, "\\2", 1, $0)
	if (id == $0) break
	# convert to RSASIGKEY-bbbb"; the "-" stops re-matches
	if (!subid(genid("RSASIGKEY-", id))) break;
    }

    # Look for new KEYIDs - map each to something unique
    while (1) {
	# Above should have filtered out existing IDs; look for new
	# ones.
	id = gensub(/^.*(keyid:) ([+=0-9a-zA-Z/]+)( .*|)$/, "\\2", 1, $0)
	if (id == $0) break
	# convert to KEYID-bbbb"; the "-" stops re-matches
	if (!subid(genid("KEYID-", id))) break
    }

    print
}
