function summary(div_id, json) {

    // Order the list so that the most recent commit is first.
    json.sort(function(l, r) {
	return r.commit.rank - l.commit.rank
    })

    var titles = [
	"Rank", "Commit", "Date",
	"Passed", "Failed", "Unresolved", "Untested", "Total",
	"Start Time", "Run Time",
	"Directory"
    ]

    // "titles" -> "property"
    var map = {
	"Rank": ["commit", "rank"],
	"Date": ["commit", "committer_date"],
	"Commit": ["commit", "abbreviated_commit_hash"],
	"Run Time": ["runtime"],
    }
    titles.forEach(function(title) {
	if (!map.hasOwnProperty(title)) {
	    property = title.toLowerCase().replace(" ", "_")
	    map[title] = [property]
	}
    })

    var values = []
    json.forEach(function(d) {
	var row = []
	titles.forEach(function(title) {
	    var value = d
	    map[title].forEach(function(property) {
		value = (value.hasOwnProperty(property)
			 ? value[property]
			 : "")
	    })
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
		    } else if (col.cellIndex == 1) {
			var child = col.childNodes[0]
			var text = child.data
			var a = document.createElement("a")
			var href = "https://github.com/libreswan/libreswan/commit/" + text
			a.setAttribute("href", href)
			a.appendChild(document.createTextNode(text))
			col.replaceChild(a, child)
		    }
		}
	    },
	})
}
