// Callback with the loaded and cleaned up summary.json data set.

var lsw_result_names = [
    "passed",
    "failed",
    "unresolved",
    "untested"
]

function lsw_load_summary(file, f) {
    d3.json(file, function(error, json) {
	if (error) {
	    console.log(error)
	    return
	}

	// Start with rank order
	json = json.sort(function(l, r) {
	    return +l.rank - +r.rank
	})

	// Clean up the data set.
	for (var i = 0; i < json.length; i++) {
	    d = json[i]
	    d.date = new Date(d.date)
	    d.start_time = new Date(d.start_time)
	    d.rank = +d.rank
	    d.commits = (i > 0
			 ? json[i-1].revision + "..." + d.revision
			 : d.revision)

	    // accumulate results
	    d.results = []
	    d.totals = [0]
	    var total = 0
	    lsw_result_names.forEach(function(result) {
		var result = (d.hasOwnProperty(result)
			      ? +d[result]
			      : 0)
		total += result
		d.results.push(result)
		d.totals.push(total)
	    })
	}

	f(json)
    })
}
