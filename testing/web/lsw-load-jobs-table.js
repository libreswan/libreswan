function lsw_load_jobs_table(div_id, directories) {

    var queue = d3.queue()
    directories.forEach(function(directory) {
	queue.defer(d3.json, directory + "status.json")
    })

    queue.awaitAll(function(error, results) {
	if (error) {
	    console.log(error)
	    return
	}

	var titles = [
	    directories[0] ? "Directory" : "Current Time",
	    "Job",
	    "Started",
	    "Last Update",
	    "Details",
	]

	var values = []
	for (var i = 0; i < results.length; i++) {
	    var status = results[i]
	    var directory = directories[i]
	    values.push([
		directory ? directory : i == 0 ? lsw_date2iso(new Date()) : "",
		status.job,
		lsw_date2iso(new Date(status.start)),
		lsw_date2iso(new Date(status.date)),
		status.details,
	    ])
	}

	document.getElementById(div_id)
            .TidyTable({
		enableCheckbox : false,
		enableMenu     : false,
            }, {
		columnTitles : titles,
		columnValues : values,
		postProcess: {
		    column: !directories[0] ? null : function postProcessColumn(col) {
			// Link directory
			if (col.cellIndex == 0) {
			    var child = col.childNodes[0]
			    var text = child.data
			    if (text) {
				var a = document.createElement("a")
				a.setAttribute("href", text)
				a.appendChild(document.createTextNode(text))
				col.replaceChild(a, child)
			    }
                        }
                    }
                },
            })
    })
}
