// lsw-table.js

// Convert the nested columns:
//
//     [{[{}]}, ...]
//
// into an array of header rows:
//
//     [{}, ...]
//     [{}, ...]
//
// with a span value
//
// This is effectively a leaf walk.

function lsw_table_headers(recursion, start, table, headers) {
    var this_row = 0
    if (table.length) {
	table.span = 0
	table.forEach(function(column) {
	    // Keep track of the number of rows below this one.
	    var rows_below = lsw_table_headers(recursion + 1,
					       start + table.span,
					       column, headers)
	    // If this column is short a few rows, add them.
	    for (var row = rows_below; row < this_row; row++) {
		headers[row].push({
		    span: column.span
		})
	    }
	    this_row = Math.max(this_row, rows_below)
	    table.span += column.span
	})
	// If this row is missing, add it with skips to the left; but
	// not the very first row as that has no title.
	if (recursion > 0) {
	    while (headers.length <= this_row) {
		headers.push([{
		    span: start,
		}])
	    }
	    headers[this_row].push(table)
	}
    } else {
	headers[0].push(table)
	table.span = 1
    }
    return this_row + 1
}

function lsw_table(table) {

    // Recursively convert the columns into rows of headers.

    table.headers = [[]]
    table.span = lsw_table_headers(0, 0, table.columns, table.headers)
    table.headers.reverse()

    // Fuge up "table.column" inheritance

    table.headers.forEach(function(header) {
	header.forEach(function(column) {
	    if (column.title === undefined) {
		column.title = ""
	    }
	    if (column.value === undefined) {
		column.index = column.title.toLowerCase().replace(/ /g, "_")
		column.value = function(row) {
		    return (row[column.index] ? row[column.index] : "")
		}
	    }
	    if (column.html === undefined) {
		column.html = column.value
	    }
	    if (column.sort === undefined) {
		column.sort = function(l, r) {
		    var lv = column.value(l)
		    var rv = column.value(r)
		    if (lv < rv) {
			return -1
		    } else if (lv > rv) {
			return 1
		    } else {
			return 0
		    }
		}
	    }
	})
    })

    // Fudge up "table.sort" inheritance.

    if (table.sort === undefined) {
	table.sort = {}
    }
    if (table.sort.column === undefined) {
	table.sort.column = table.headers[table.headers.length - 1][0]
    }
    if (table.sort.assending === undefined) {
	table.sort.assending = false
    }

    // Fudge up select inheritance

    if (table.select === undefined) {
	table.select = {}
    }

    // Compute the table rows from the table.data

    table.rows = []
    table.data.forEach(function(data) {
	var row = {
	    data: data,
	    // XXX: selected used to rebuild the table after a sort.
	    selected: false,
	    table: table,
	    columns: []
	}
	table.headers[table.headers.length - 1].forEach(function(column) {
	    row.columns.push({
		text: column.html(data),
		row: row,
		column: column,
	    })
	})
	table.rows.push(row)
    })

    // Create the table; and save the table wide data.

    d3.select("#" + table.id)
	.append("table").attr("class", table.id)
	.data([table])

    // Create the headers from the column

    d3.select("table." + table.id)
	.append("thead").attr("class", table.id)
	.selectAll("tr")
	.data(function(table) {
	    // return all the rows
	    return table.headers
	})
	.enter()
	.append("tr")
	.selectAll("th")
	.data(function(header) {
	    // return all the columns
	    return header
	})
	.enter()
	.append("th")
	.html(function(column) {
	    // return this column
	    return column && column.title || ""
	})
	.each(function(column) {
	    var styles = column.style && column.style.header
	    if (styles) {
		var selection = d3.select(this)
		Object.keys(styles).forEach(function(name) {
		    value = styles[name]
		    selection.style(name, value)
		})
	    }
	})
	.attr("colspan", function(column) {
	    return column.span
	})
	.on("click", function(column, index) {
	    // only sort lowest level columns
	    if (column.columns) {
		return
	    }
	    // clear any existing sort
	    if (table.sort.column == column) {
		table.sort.assending = !table.sort.assending
	    } else {
		table.sort.column = column
		table.sort.assending = false
	    }
	    lsw_table_body(table)
	})

    lsw_table_body(table)
}

function lsw_table_body(table) {

    // always sort

    table.rows.sort(function (left_row, right_row) {
	if (table.sort.assending) {
	    return table.sort.column.sort(left_row.data, right_row.data)
	} else {
	    return table.sort.column.sort(right_row.data, left_row.data)
	}
    })

    // cheat - rebuild the table body

    d3.selectAll("tbody." + table.id)
	.remove()

    var tr = d3.select("table." + table.id)
	.append("tbody").attr("class", table.id)
	.selectAll("tr")
	.data(function(table) {
	    return table.rows
	})
        // add the table row
	.enter()
	.append("tr")
	.style("background-color", function(row) {
	    return row.table.select.row && row.selected ? "lightgrey" : ""
	})
	.on("click", function(row) {
	    if (row.table.select.row) {
		lsw_table_select_row(table.id, row.data)
	    }
 	})
        // add the row data
	.selectAll("td")
	.data(function(row) {
	    return row.columns
	})
	.enter()
	.append("td")
	.html(function(element) {
	    return element.text
	})
	.each(function(element, index) {
	    var styles = element.column.style && element.column.style.body
	    if (styles) {
		var selection = d3.select(this)
		Object.keys(styles).forEach(function(name) {
		    value = styles[name]
		    selection.style(name, value)
		})
	    }
	})
}

function lsw_table_select_row(table_id, selection) {
    // toggle SELECTION's "background"
    d3.selectAll("tbody." + table_id + " > tr")
	.filter(function(row) {
	    return row.data == selection
	})
	.style("background-color", function(row) {
	    // XXX: row.selected still used when rebuilding the table
	    // after a sort.
	    row.selected = !row.selected
	    // var background = d3.select(this).style("background-color")
	    //
	    // lightgrey comes back as some rgb value, chrome and
	    // firefox have different defaults.  Perhaps a style?
	    //
	    // row.selected = (background != "" && background != "transparent")
	    return (row.selected
		    ? "lightgrey"
		    : "transparent")
	})
    // select all with non-blank backgrounds
    var data = d3.selectAll("tbody." + table_id + " > tr")
	.filter(function(row) {
	    // var background = d3.select(this).style("background-color")
	    // return background != "" && background != "transparent"
	    return row.selected
	})
	.data()
	.map(function(row) {
	    return row.data
	})

    // now tell the client found in the table's data.
    var table = d3.select("table." + table_id).data()[0]
    table.select.row(data)
}
