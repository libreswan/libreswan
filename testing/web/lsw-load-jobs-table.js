
function lsw_load_jobs_table(jobs_id, directories) {

    var queue = d3.queue()
    directories.forEach(function(directory) {
	queue.defer(d3.json, directory + "status.json")
    })

    queue.awaitAll(function(error, results) {

	if (error) {
	    console.warn(error)
	    return
	}

	// Merge directory/results
	for (var i = 0; i < directories.length; i++) {
	    results[i].directory = directories[i]
	}

	var columns = [
	    {
		title: directories[0] ? "Directory" : "Current Time",
		value: function(status) {
		    return status.directory
		},
		html: function(status) {
		    if (status.directory.length > 0) {
			return ("<a href=\"" + status.directory + "\">"
				+ status.directory
				+ "</a>")
		    } else {
			return lsw_date2iso(new Date())
		    }
		}
	    },
	    {
		title: "Job",
	    },
	    {
		title: "Started",
		value: function(status) {
		    return lsw_date2iso(new Date(status.start))
		},
	    },
	    {
		title: "Last Update",
		value: function(status) {
		    return lsw_date2iso(new Date(status.date))
		},
	    },
	    {
		title: "Details",
	    },
	]

	lsw_table({
	    id: jobs_id,
	    data: results,
	    columns: columns,
	})
    })
}
