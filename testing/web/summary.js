function summary(div_id, json) {

    // Order the list so that the most recent commit is first.
    json.sort(function(l, r) {
	return r.rank - l.rank
    })

    var titles = [
	"Rank", "Commits", "Last Commit Date",
	"Passed", "Failed", "Unresolved", "Untested", "Total",
	"Start Time", "Run Time",
	"Directory"
    ]

    // "titles" -> "property"
    var map = {
	"Last Commit Date": "date",
	"Run Time": "runtime"
    }
    titles.forEach(function(title) {
	if (!map.hasOwnProperty(title)) {
	    property = title.toLowerCase().replace(" ", "_")
	    map[title] = property
	}
    })

    var values = []
    json.forEach(function(d) {
	var row = []
	titles.forEach(function(title) {
	    title = map[title]
	    var value = (d.hasOwnProperty(title)
			 ? d[title]
			 : "")
	    if (value instanceof Date) {
		value = lsw_date2iso(value)
	    }
	    row.push(value)
	})
	values.push(row)
    })

    // Init Tidy-Table
    document.getElementById(div_id)
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
	})
}
