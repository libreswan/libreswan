// lsw-compare-table.js

// Load up the result list and then generate a comparison table.

var lsw_compare_table_id = "compare"

function lsw_compare_summary(results_summaries) {

    // Filter out the "current" row?

    var queue = d3.queue()

    var requests = []
    results_summaries.forEach(function(results_summary) {
	if (results_summary.directory !== undefined &&
	    results_summary.test_results === undefined) {
	    requests.push(results_summary)
	    var request = results_summary.directory + "/results.json"
	    queue.defer(d3.json, request)
	}
    })

    // what happens if there is more than one load?

    queue.awaitAll(function(error, test_results) {
	if (error) {
	    return console.warn(error)
	}

	// fill in the now-loaded results.
	for (var i = 0; i < test_results.length; i++) {
	    requests[i].test_results = test_results[i]
	}

	lsw_compare_table(results_summaries)
    })
}

function lsw_compare_table(results_summaries) {

    // A dictionary mapping test names to loaded results.

    var dictionary = {}
    results_summaries.forEach(function(results_summary) {
	if (results_summary.test_results) {
	    results_summary.test_results.forEach(function(test_result) {
		var name = test_result.test_name
		if (dictionary[name] === undefined) {
		    dictionary[name] = { }
		}
		dictionary[name][results_summary.directory] = test_result
	    })
	}
    })

    // Convert the dictionary into a comparison table containing just
    // the items that are different.

    var values = []
    for (var name in dictionary) {
	var test_results = dictionary[name]
	if (results_summaries.length < 2) {
	    values.push({
		test_name: name,
		test_results: test_results,
	    })
	} else {
	    var result = {}
	    var test_kind = {}
	    var test_status = {}
	    var test_errors = {}
	    for (var directory in test_results) {
		var test_result = test_results[directory]
		result[test_result.result] = true
		test_kind[test_result.test_kind] = true
		test_status[test_result.test_status] = true
		// are the error strings different, keys has no
		// defined order.
		var errors = "errors"
		Object.keys(test_result.errors).sort().forEach(function(host) {
		    errors += ":" + host
		    test_result.errors[host].sort().forEach(function(error) {
			errors += ":" + error
		    })
		})
		test_errors[errors] = true
	    }
	    if (Object.keys(result).length > 1
		|| Object.keys(test_kind).length > 1
		|| Object.keys(test_status).length > 1
		|| Object.keys(test_errors).length > 1) {
		values.push({
		    test_name: name,
		    test_results: test_results,
		})
	    }
	}
    }

    // Go through the filtered values and see which columns need
    // displaying.

    var test_kind = {}
    var test_status = {}
    values.forEach(function(value) {
	for (var directory in value.test_results) {
	    var test_result = value.test_results[directory]
	    test_kind[test_result.test_kind] = true
	    test_status[test_result.test_status] = true
	}
    })

    var columns = [
	{
	    title: "",
	    columns: [
		{
		    title: "Test Name",
		    body_align: "left"
		},
	    ],
	}
    ]

    if (Object.keys(test_kind).length == 1) {
	// force value into a new context
	Object.keys(test_kind).forEach(function(value) {
	    columns[0].columns.push({
		title: "Kind",
		value: function(row) {
		    return value
		}
	    })
	})
    }

    if (Object.keys(test_status).length == 1) {
	// force value into a new context
	Object.keys(test_status).forEach(function(value) {
	    columns[0].columns.push({
		title: "Status",
		value: function(row) {
		    return value
		}
	    })
	})
    }

    results_summaries.forEach(function(results_summary) {
	var results_column = {
	    title: lsw_commits_html(results_summary.commits),
	    header_align: "left",
	    columns: []
	}
	if (Object.keys(test_kind).length > 1) {
	    results_column.columns.push({
		directory: results_summary.directory,
		title: "Kind",
		value: function(row) {
		    var result = row.test_results[this.directory]
		    if (result == undefined) {
			return ""
		    }
		    var value = result.test_kind
		    if (value == undefined) {
			return ""
		    }
		    return value
		},
	    })
	}
	if (Object.keys(test_status).length > 1) {
	    results_column.columns.push({
		directory: results_summary.directory,
		title: "Status",
		value: function(row) {
		    var result = row.test_results[this.directory]
		    if (result == undefined) {
			return ""
		    }
		    var value = result.test_status
		    if (value == undefined) {
			return ""
		    }
		    return value
		},
	    })
	}
	results_column.columns.push({
	    directory: results_summary.directory,
	    title: "Result",
	    value: function(row) {
		var result = row.test_results[this.directory]
		if (result == undefined) {
		    return ""
		}
		var value = result.result
		if (value == undefined) {
		    return ""
		}
		return value
	    },
	    html: function(row) {
		var value = this.value(row)
		if (value) {
		    return ("<a href=\""
			    + this.directory + "/" + row.test_name + "/OUTPUT"
			    + "\">"
			    + value
			    + "</a>")
		} else {
		    return ""
		}
	    },
	})
	results_column.columns.push({
	    directory: results_summary.directory,
	    title: "Issues",
	    value: function(row) {
		if (this.title in row.test_results) {
		    return row.test_results[this.title].result
		} else {
		    return ""
		}
	    },
	    body_align: "left",
	    html: function(row) {
		var result = row.test_results[this.directory]
		if (result == undefined) {
		    return ""
		}
		var test_host_names = (result.test_host_names !== undefined
				       ? result.test_host_names
				       : result.host_names !== undefined
				       ? result.host_names
				       : null)
		if (!test_host_names) {
		    return ""
		}
		var br = false
		var html = ""
		var directory = this.directory
		test_host_names.forEach(function(host) {
		    if (br) {
			html += "<br/>"
		    }
		    br = true
		    html += host + ":"
		    if (result.errors[host] === undefined
			|| result.errors[host].length == 0) {
			html += "passed"
			return
		    }
		    sep = ""
		    result.errors[host].forEach(function(error) {
			html += sep
			sep = ", "
			var href = null
			var value = ""
			if (error == "passed") {
			    value = "passed"
			} else if (error == "baseline-missing") {
			    // Probably a new test.
			    value = "previous-missing"
			} else if (error == "output-different"
				   || error == "output-whitespace") {
			    href = result.output_directory + "/" + host + ".console.diff"
			    value = error
			} else if (error == "output-unchecked") {
			    href = result.output_directory + "/" + host + ".console.txt"
			    value = error
			} else if (error == "output-truncated") {
			    href = result.output_directory + "/" + host + ".console.verbose.txt"
			    value = error
			} else {
			    href = result.output_directory
			    value = error
			}
			if (href) {
			    html += "<a href=\"" + directory + "/" + href + "\">" + value + "</a>"
			} else {
			    html += value
			}
		    })
		})
		return html
	    },
	})
	columns.push(results_column)
    })

    // hack

    d3.select("table." + lsw_compare_table_id).remove()

    lsw_table({
	id: lsw_compare_table_id,
	results_summaries: results_summaries,
	data: values,
	columns: columns,
    })

}

