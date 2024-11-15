// lsw-compare-table.js

// Load up the result list and then generate a comparison table.

var lsw_compare_table_id = "compare-results"

function lsw_compare_test_runs(test_runs) {

    console.log("compare test runs", test_runs)

    // Filter out the "current" row?

    let queue = d3.queue()

    // may be sparse so maintain an array of the actual requests
    let requested_runs = []

    for (const run of test_runs) {
	if (run.directory !== undefined &&
	    run.test_results === undefined) {
	    requested_runs.push(run)
	    let request = run.directory + "/results.json"
	    queue.defer(d3.json, request)
	}
    }

    // what happens if there is more than one load?

    queue.awaitAll(function(error, results) {
	if (error) {
	    return console.warn(error)
	}

	// fill in the now-loaded results.
	for (let i = 0; i < results.length; i++) {
	    requested_runs[i].test_results =
		results[i].map((result) => new TestResult(result))
	}

	lsw_compare_table(test_runs)
    })
}

function lsw_compare_table(test_runs) {

    // Edit the URL adding "?run=RUN&run=RUN..." so that a copied URL
    // includes the currently selected test results (the load code
    // knows how to parse this).
    //
    // It seems that passing in "" doesn't reset the suffix but ".",
    // seemingly, does!?!

    let url = ""
    let sep = "?"
    for (const run of test_runs) {
	if (run.directory !== undefined) {
	    url = url + sep + "run=" + run.directory
	    sep = "&"
	}
    }
    if (history.state === null) {
	if (url.length > 0) {
	    history.pushState("here", '', url)
	}
    } else if (url.length === 0) {
	history.back()
    } else {
	history.replaceState("here", '', url)
    }

    // Create a test_dictionary mapping each test name onto a
    // (possibly sparse) array of directory results.

    let test_dictionary = {}
    test_runs.forEach(function(run, run_index) {
	if (run.test_results) {
	    for (const test_result of run.test_results) {
		let name = test_result.test_name
		if (test_dictionary[name] === undefined) {
		    test_dictionary[name] = new Array(test_runs.length)
		}
		test_dictionary[name][run_index] = test_result
	    }
	}
    })

    // Convert the test dictionary into an array.

    let results = []
    for (const test_name of Object.keys(test_dictionary)) {
	let test_results = test_dictionary[test_name]
	results.push({
	    test_name: test_name,
	    test_results: test_results,
	})
    }

    // Filter the results array leaving only stuff that needs to be
    // displayed.

    if (test_runs.length > 1) {
	// Only need to filter when there is more than one test run
	// involved.
	results = results.filter(function(test) {
	    // Use result[0] as a baseline that all other results
	    // should match
	    let baseline = test.test_results[0]
	    // A missing result is presumably from it being
	    // added/deleted, always display it.
	    if (!baseline) {
		return true
	    }
	    // For the issues, convert them to a string so any change
	    // is detected.
	    let issue_string = function(test_result) {
		let issues = "issues"
		for (const host of Object.keys(test_result.issues).sort()) {
		    issues += ":" + host
		    for (const issue of test_result.issues[host].sort()) {
			issues += ":" + issue
		    }
		}
		return issues
	    }
	    let baseline_issues = issue_string(baseline)
	    return test.test_results.slice(1).some(function(current) {
		if (!current) {
		    return true
		}
		if (baseline.result != current.result) {
		    return true
		}
		if (baseline.test_kind != current.test_kind) {
		    return true
		}
		if (baseline.test_status != current.test_status) {
		    return true
		}
		if (baseline_issues != issue_string(current)) {
		    return true
		}
	    })
	})
    }

    let columns = [
	{
	    title: "Test Name",
	    style: {
		body: {
		    "text-align": "left",
		},
	    },
	    value: function(row) {
		return row.test_name
	    },
	},
    ]

    // If "test_kind" and/or "test_status" is identical across the
    // entire table, exclude them in the side-by-side comparison.
    // Instead display them once, next to name.

    let same_kind = undefined
    let same_status = undefined
    for (const test of results) {
	for (const result of test.test_results) {
	    if (result) {
		same_kind = (same_kind === undefined ? result.test_kind
			     : same_kind == result.test_kind ? same_kind
			     : false)
		same_status = (same_status === undefined ? result.test_status
			     : same_status == result.test_status ? same_status
			     : false)
	    }
	}
    }

    if (same_kind) {
	columns.push({
	    title: "Kind",
	    value: function(row) {
		return same_kind
	    }
	})
    }

    if (same_status) {
	columns.push({
	    title: "Status",
	    value: function(row) {
		return same_status
	    }
	})
    }

    test_runs.forEach(function(run, run_index) {
	let results_column = []
	results_column.title = run.html_commits()
	results_column.style = {
	    header: {
		"text-align": "left",
		"vertical-align": "top",
	    },
	}
	if (!same_kind) {
	    results_column.push({
		directory: run.directory,
		title: "Kind",
		value: function(row) {
		    let result = row.test_results[run_index]
		    if (result == undefined) {
			return ""
		    }
		    let value = result.test_kind
		    if (value == undefined) {
			return ""
		    }
		    return value
		},
	    })
	}
	if (!same_status) {
	    results_column.push({
		directory: run.directory,
		title: "Status",
		value: function(row) {
		    let result = row.test_results[run_index]
		    if (result == undefined) {
			return ""
		    }
		    let value = result.test_status
		    if (value == undefined) {
			return ""
		    }
		    return value
		},
	    })
	}
	results_column.push({
	    directory: run.directory,
	    title: "Result",
	    value: function(row) {
		let result = row.test_results[run_index]
		if (result == undefined) {
		    return ""
		}
		let value = result.result
		if (value == undefined) {
		    return ""
		}
		return value
	    },
	    html: function(row) {
		let value = this.value(row)
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
	results_column.push({
	    directory: run.directory,
	    title: "Issues",
	    value: function(row) {
		if (this.title in row.test_results) {
		    return row.test_results[run_index].result
		} else {
		    return ""
		}
	    },
	    style: {
		body: {
		    "text-align": "left",
		},
	    },
	    html: function(row) {
		let result = row.test_results[run_index]
		if (!result) {
		    return ""
		}
		return result.html_issues(this.directory + "/" + result.test_name + "/")
	    },
	})
	columns.push(results_column)
    })

    // hack

    d3.select("table." + lsw_compare_table_id).remove()

    lsw_table({
	id: lsw_compare_table_id,
	test_runs: test_runs,
	data: results,
	columns: columns,
    })

}
