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
    let this_row = 0
    if (table.length) {
	table.span = 0
	for (const column of table) {
	    // Keep track of the number of rows below this one.
	    let rows_below = lsw_table_headers(recursion + 1,
					       start + table.span,
					       column, headers)
	    // If this column is short a few rows, add them.
	    for (let row = rows_below; row < this_row; row++) {
		headers[row].push({
		    span: column.span
		})
	    }
	    this_row = Math.max(this_row, rows_below)
	    table.span += column.span
	}
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

    for (const header of table.headers) {
	for (const column of header) {
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
		    let lv = column.value(l)
		    let rv = column.value(r)
		    let diff
		    if (lv < rv) {
			diff = -1
		    } else if (lv > rv) {
			diff = 1
		    } else {
			diff = 0
		    }
		    return diff
		}
	    }
	}
    }

    // Fudge up "table.sort" inheritance.

    if (table.sort === undefined) {
	table.sort = {}
    }
    if (table.sort.column === undefined) {
	table.sort.column = table.headers[table.headers.length - 1][0]
    }
    if (table.sort.ascending === undefined) {
	table.sort.ascending = false
    }

    // Fudge up select inheritance

    if (table.select === undefined) {
	table.select = {}
    }

    // Compute the table rows from the table.data

    table.rows = []
    for (const data of table.data) {
	let row = {
	    data: data,
	    // XXX: selected used to rebuild the table after a sort.
	    selected: false,
	    table: table,
	    columns: []
	}
	for (const column of table.headers[table.headers.length - 1]) {
	    row.columns.push({
		text: column.html(data),
		row: row,
		column: column,
	    })
	}
	table.rows.push(row)
    }

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
	    let styles = column.style && column.style.header
	    if (styles) {
		let selection = d3.select(this)
		for (const name of Object.keys(styles)) {
		    value = styles[name]
		    selection.style(name, value)
		}
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
		table.sort.ascending = !table.sort.ascending
	    } else {
		table.sort.column = column
		table.sort.ascending = false
	    }
	    lsw_table_body(table)
	})

    lsw_table_body(table)
}

function lsw_table_body(table) {

    // always sort

    table.rows.sort(function (left_row, right_row) {
	let column = table.sort.column
	if (table.sort.ascending) {
	    return column.sort(left_row.data, right_row.data)
	} else {
	    return column.sort(right_row.data, left_row.data)
	}
    })

    // cheat - rebuild the table body

    d3.selectAll("tbody." + table.id)
	.remove()

    let tr = d3.select("table." + table.id)
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
		console.log("click row", row.data)
		lsw_table_select_rows(table.id, new Set([row.data]))
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
	    let styles = element.column.style && element.column.style.body
	    if (styles) {
		let selection = d3.select(this)
		for (const name of Object.keys(styles)) {
		    value = styles[name]
		    selection.style(name, value)
		}
	    }
	})
}

function lsw_table_select_rows(table_id, selections) {

    console.log("selecting rows", selections)

    // toggle SELECTION's "background"
    d3.selectAll("tbody." + table_id + " > tr")
	.filter(function(row) {
	    return selections.has(row.data)
	})
	.style("background-color", function(row) {
	    // XXX: row.selected still used when rebuilding the table
	    // after a sort.
	    row.selected = !row.selected
	    // let background = d3.select(this).style("background-color")
	    //
	    // lightgrey comes back as some rgb value, chrome and
	    // firefox have different defaults.  Perhaps a style?
	    //
	    // row.selected = (background != "" && background != "transparent")
	    return (row.selected
		    ? "lightgrey"
		    : "transparent")
	})

    // select rows all with non-blank (i.e., selected) backgrounds
    let data = d3.selectAll("tbody." + table_id + " > tr")
	.filter(function(row) {
	    // let background = d3.select(this).style("background-color")
	    // return background != "" && background != "transparent"
	    return row.selected
	})
	.data()
	.map(function(row) {
	    return row.data
	})

    // now tell the client found in the table's data.
    let table = d3.select("table." + table_id).data()[0]
    table.select.row(data)
}
