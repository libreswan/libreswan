// lsw-table.js

// Convert the nested columns:
//
//     [{[{}]}, ...]
//
// into lists of headers:
//
//     [{}, ...]
//     [{}, ...]
//
// with a span value

function lsw_table_headers(columns, headers, depth) {
    if (headers[depth] === undefined) {
	headers[depth] = []
    }
    var span = 0
    columns.forEach(function(column) {
	headers[depth].push(column)
	if (column.columns === undefined) {
	    column.span = 1
	} else {
	    column.span = lsw_table_headers(column.columns, headers, depth + 1)
	}
	span += column.span
    })
    return span
}

function lsw_table(table) {

    // Recursively convert the columns into rows of headers.

    table.headers = []
    table.span = lsw_table_headers(table.columns, table.headers, 0)

    // Fuge up "table.column" inheritance

    table.headers.forEach(function(header) {
	header.forEach(function(column) {
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
	table.sort.assending = true
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
	.append("table")
	.attr("class", table.id)
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
	    return column.title
	})
	.style("text-align", function(column) {
	    return column.header_align || null
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
		table.sort.assending = true
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

    d3.select("table." + table.id)
	.selectAll("tbody." + table.id)
	.remove()

    var tr = d3.select("table." + table.id)
	.append("tbody").attr("class", table.id)
	.selectAll("tr")
	.data(function(table) {
	    return table.rows
	})
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

    var td = d3.select("table." + table.id)
	.select("tbody." + table.id)
	.selectAll("tr")
	.selectAll("td")
	.data(function(row) {
	    return row.columns
	})
	.enter()
	.append("td")
	.html(function(column) {
	    return column.text
	})
	.style("text-align", function(column) {
	    return column.column.body_align || null
	})
}

function lsw_table_select_row(table_id, selection) {
    // toggle SELECTION's "background"
    d3.select("table." + table_id)
	.selectAll("tbody." + table_id)
	.selectAll("tr")
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
    var data = d3.select("table." + table_id)
	.selectAll("tbody." + table_id)
	.selectAll("tr")
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

