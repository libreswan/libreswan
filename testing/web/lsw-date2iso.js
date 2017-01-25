// Convert the Date() to the truncated ISO string: YYYY-MM-DD HH:MM.
function lsw_date2iso(d) {
    // Force to UTC?
    d = d.toISOString()
    d = d.match("([^T]*)T([0-9]*:[0-9]*)")
    return d[1] + " " + d[2]
}

// include seconds
function lsw_date2iso_long(d) {
    // Force to UTC?
    d = d.toISOString()
    d = d.match("([^T]*)T([0-9]*:[0-9]*:[0-9]*)")
    return d[1] + " " + d[2]
}
