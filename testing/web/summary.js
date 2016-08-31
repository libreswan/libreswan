function summary(json) {
    window.addEventListener('load', function() {
	$.ajaxSetup({ cache: false });

	// this gets a not well-formed warning
	$.getJSON(json, function(summary) {

	    // Clean up the data set.
	    summary.forEach(function(d) {
		d.date = new Date(d.date)
	    })

	    // Re-order the list with most recent first.
	    summary.sort(function(l, r) {
		return r.date > l.date
	    })

	    var titles = [ "Revision", "Date",
			   "Passed", "Failed", "Unresolved", "Untested", "Total",
			   "Start Time", "Run Time",
			   "Directory" ]

	    var values = []
	    summary.forEach(function(d) {
		values.push([
		    d.revision,
		    lsw_date2iso(d.date),
		    d.passed,
		    d.failed,
		    (d.hasOwnProperty('unresolved') ? d.unresolved : ""),
		    (d.hasOwnProperty('untested') ? d.untested : ""),
		    d.total,
		    lsw_date2iso(new Date(d.start_time)),
		    d.runtime,
		    d.directory
		])
	    })

            // Init Tidy-Table
            document.getElementById('container')
		.TidyTable({
                    enableCheckbox : false,
                    enableMenu     : false,
		}, {
                    columnTitles : titles,
                    columnValues : values,
		    postProcess: {
			column: function postProcessColumn(col) {
			    // Test Directory is last
			    if (col.cellIndex == titles.length - 1) {
				var child = col.childNodes[0]
				var text = child.data
				var a = document.createElement("a")
				a.setAttribute("href", text)
				a.appendChild(document.createTextNode(text))
				col.replaceChild(a, child)
			    }
			}
		    },
		});
	});
    })
}

