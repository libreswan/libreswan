function lsw_summary_graph_click_test_run(table_id, summary_test_run) {
    window.location = "../" + summary_test_run.directory
}

function output_file(result, suffix) {
    return result.test_name + "/OUTPUT/" + suffix
}

function results(div_id, json_file) {
    d3.json(json_file, function(error, results) {

	if (error) {
	    return console.warn(error)
	}

	let columns = [
	    {
		title: "Test",
		value: function(result) {
		    return result.test_name
		},
		html: function(result) {
		    return ("<a href=\""
			    + result.test_name
			    + "\">"
			    + result.test_name
			    + "</a>")
		},
	    },
	    {
		title: "Kind",
		value: function(result) {
		    return (result.test_kind !== undefined
			    ? result.test_kind
			    : "")
		},
	    },
	    {
		title: "Status",
		value: function(result) {
		    return (result.test_status !== undefined
			    ? result.test_status
			    : result.expected_result !== undefined
			    ? result.expected_result
			    : "")
		},
	    },
	    {
		title: "Result",
	    },
	    {
		title: "Issues",
		html: function(result) {
		    if (!result || result.result == "untested") {
			return ""
		    }
		    let test_guest_names =
			(result.test_guest_names !== undefined ? result.test_guest_names :
			 result.test_host_names !== undefined ? result.test_host_names :
			 result.host_names !== undefined ? result.host_names :
			 null)
		    if (!test_guest_names) {
			return ""
		    }
		    let br = false
		    let html = ""
		    for (const host of test_guest_names) {
			if (br) {
			    html += "<br/>"
			}
			br = true
			html += host + ":"
			if (result.errors[host] === undefined
			    || result.errors[host].length == 0) {
			    html += "passed"
			} else {
			    let sep = ""
			    for (const error of result.errors[host]) {
				html += sep
				sep = ", "
				let href = null
				let value = ""
				if (error == "passed") {
				    value = "passed"
				} else if (error == "output-different"
					   || error == "output-whitespace") {
				    href = output_file(result, host + ".console.diff")
				    value = error
				} else if (error == "output-unchecked") {
				    href = output_file(result, host + ".console.txt")
				    value = error
				} else if (error == "output-truncated") {
				    href = output_file(result, host + ".console.verbose.txt")
				    value = error
				} else if (error == "EXPECTATION"
					   || error == "ASSERTION") {
				    href = output_file(result, host + ".pluto.log")
				    value = error
				} else {
				    href = output_file(result, "")
				    value = error
				}
				if (href) {
				    html += "<a href=\"" + href + "\">" + value + "</a>"
				} else {
				    html += value
				}
			    }
			}
		    }
		    return html
		},
	    },
	    {
		title: "Boot Time",
	    },
	    {
		title: "Test Time",
	    },
	    {
		title: "Total Time",
	    },
	]

	lsw_table({
	    id: div_id,
	    data: results,
	    columns: columns,
	})
    })
}
