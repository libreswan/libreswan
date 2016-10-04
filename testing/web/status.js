function status(div_id, status_json) {

    window.addEventListener('load', function() {

	d3.json(status_json, function(error, status_files) {

	    var queue = d3.queue()
	    status_files.forEach(function(status_file) {
		queue.defer(d3.json, status_file)
	    })

	    queue.awaitAll(function(error, results) {
		var titles = [ "Directory", "Job", "Started", "Last Update", "Details" ]
		values = []
		if (error) {
		    values.push(["error", files])
		} else {
		    for (var i = 0; i < results.length; i++) {
			var status = results[i]
			var directory = status_files[i].match("(.*)/")[1]
			// should be table within table
			values.push([
			    directory,
			    status.job,
			    lsw_date2iso(new Date(status.start)),
			    lsw_date2iso(new Date(status.date)),
			    status.details
			])
		    }
		}

		document.getElementById(div_id)
		    .TidyTable({
			enableCheckbox : false,
			enableMenu     : false,
		    }, {
			columnTitles : titles,
			columnValues : values,
			postProcess: {
			    column: function postProcessColumn(col) {
				// Link directory
				if (col.cellIndex == 0) {
				    var child = col.childNodes[0]
				    var text = child.data
				    var a = document.createElement("a")
				    a.setAttribute("href", text)
				    a.appendChild(document.createTextNode(text))
				    col.replaceChild(a, child)
				}
			    }
			},
		    })
	    })
	})
    })
}
