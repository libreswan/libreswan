
function lsw_load_jobs_table(jobs_id, paths) {

    var queue = d3.queue()
    paths.forEach(function(path) {
	queue.defer(d3.json, path + "status.json")
    })

    queue.awaitAll(function(error, results) {

	if (error) {
	    console.warn(error)
	    return
	}

	// Add in the path to the directory.
	results.forEach(function(result, i) {
	    result.directory = paths[i] + result.directory
	})

	var columns = [
	    {
		title: "Current Time",
		value: function(status) {
		    return new Date()
		},
		html: function(status) {
		    return lsw_date2iso(new Date())
		}
	    },
	    {
		title: "Directory",
		value: function(status) {
		    return status.directory
		},
		html: function(status) {
		    console.log(status)
		    if (status.directory && status.directory.length) {
			return ("<a href=\"" + status.directory + "\">"
				+ status.directory
				+ "</a>")
		    } else {
			""
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
