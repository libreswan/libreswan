function summary(json) {
    window.addEventListener('load', function() {
	$.ajaxSetup({ cache: false });

	// this gets a not well-formed warning
	$.getJSON(json, function(summary) {

	    // Re-order the list with most recent first.
	    summary.sort(function(l, r) {
		return r.date.localeCompare(l.date)
	    })

	    var titles = [ "Revision", "Date",
			   "Passed", "Failed", "Unresolved", "Untested", "Total",
			   "Start Time", "Run Time",
			   "Directory" ]
	    var values = []
	    // form the list of values
	    var date = function(d) {
		d = new Date(d)
		d = d.toISOString()
		d = d.match("([^T]*)T([0-9]*:[0-9]*)")
		return d[1] + " " + d[2]
	    }
	    summary.forEach(function(d) {
		values.push([
		    d.revision, date(d.date),
		    d.passed, d.failed,
		    (d.hasOwnProperty('unresolved') ? d.unresolved : ""),
		    (d.hasOwnProperty('untested') ? d.untested : ""),
		    d.total,
		    date(d.start_time),
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

