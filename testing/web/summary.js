function summary(json) {
    window.addEventListener('load', function() {
	$.ajaxSetup({ cache: false });

	// this gets a not well-formed warning
	$.getJSON(json, function(summary) {

	    // Re-order the list with most recent first.
	    summary.sort(function(l, r) {
		return r.date.localeCompare(l.date)
	    })

	    var titles = [ "Date", "Passed", "Failed",
			   "Unresolved", "Untested", "Total",
			   "Run Time", "Directory" ]
	    var values = []
	    // form the list of values
	    summary.forEach(function(d) {
		var unresolved = (d.hasOwnProperty('incomplete')
				  ? d.incomplete
				  : d.hasOwnProperty('unresolved')
				  ? d.unresolved
				  : "")
		var untested = (d.hasOwnProperty('untested')
				? d.untested
				: "")
		// yes Total, not total
		values.push([d.date, d.passed, d.failed,
			     unresolved, untested, d.Total,
			     d.runtime, d.directory])
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
			column: postProcessColumn,
		    },
		});
	});
    })
}

function postProcessColumn(col) {
    if (col.cellIndex == 7) { // Test Directory
	var child = col.childNodes[0]
	var text = child.data
        var a = document.createElement("a")
	a.setAttribute("href", text)
	a.appendChild(document.createTextNode(text))
	col.replaceChild(a, child)
    }
}
