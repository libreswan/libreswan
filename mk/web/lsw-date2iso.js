// Convert the Date() to the truncated ISO string: YYYY-MM-DD HH:MM.
function lsw_date2iso(d) {
    // Force to UTC?
    if (d && d.toISOString && !isNaN(d)) {
	d = d.toISOString()
	d = d.match("([^T]*)T([0-9]*:[0-9]*)")
	return d[1] + " " + d[2]
    } else {
	console.log("not a date", d, new Error().stack)
	return ">>> " + d + " <<<"
    }
}

// include seconds
function lsw_date2iso_long(d) {
    // Force to UTC?
    if (d && d.toISOString && !isNaN(d)) {
	d = d.toISOString()
	d = d.match("([^T]*)T([0-9]*:[0-9]*:[0-9]*)")
	return d[1] + " " + d[2]
    } else {
	console.log("not a date", d, new Error().stack)
	return ">>> " + d + " <<<"
    }
}

function lsw_cleanup_dates(table, fields) {
    return fields.reduce(function(values, key) {
	if (table[key]) {
	    table[key] = new Date(table[key])
	    return values
	} else {
	    console.log("date", key, "not found in", table)
	    return false
	}
    }, true)
}
