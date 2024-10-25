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

// convert Date(l)-Date(r) to hours:minutes:seconds
function subtime(l, r) {
    let ms = (Number(l) - Number(r))
    let hours = ms / 1000 / 60 / 60
    let minutes = (ms / 1000 / 60) % 60
    let seconds = (ms / 1000) % 60
    // can you believe this!
    ps = (n) => Math.trunc(n).toString().padStart(2, "0")
    // prints 0:01:00
    return Math.trunc(hours) + ":" + ps(minutes) + ":" + ps(seconds)
}
