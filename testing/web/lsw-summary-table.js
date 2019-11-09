// lsw-summary-table.js

function lsw_summary_table(table_id, summary) {

    var now = new Date()

    var columns = []

    columns.push({
	title: "Commits",
	html: function(row) {
	    // If there are no commits, this (correctly) returns a
	    // blank column.
	    return lsw_commits_html(row.commits)
	},
	value: function(row) {
	    // The value is used to sort the column.  Should the
	    // commit not be known, use NOW so that a sort will
	    // force the row to the top/bottom.
	    if (row.commits.length) {
		return row.commits[0].committer.date
	    } else {
		return now
	    }
	},
    })

    //
    // Add columns showing the broken down totals.
    //
    // The table "totals" is structured <kind> . <status> . <result>
    // . <count> and the table reflects this (with some filtering).
    //

    // First form a nested table of what titles there could be
    var kinds_seen = {}
    summary.test_runs.forEach(function(test_run) {
	// kind
	if (test_run.totals) {
	    Object.keys(test_run.totals).forEach(function(kind) {
		var statuses = test_run.totals[kind]
		var statuses_seen = kinds_seen[kind] = kinds_seen[kind] || {}
		// status
		Object.keys(statuses).forEach(function(status) {
		    var results = statuses[status]
		    var results_seen = statuses_seen[status] = statuses_seen[status] || {}
		    // result
		    Object.keys(results).forEach(function(result) {
			results_seen[result] = {}
		    })
		})
	    })
	}
    })

    // Walk this multi-level table to create the headings.
    lsw_filter_first_list(["kvmplutotest"], kinds_seen).forEach(function(kind) {

	// XXX: Exclude some historic kinds since they are no longer
	// used and just waste space.
	if (kind == "skiptest") return
	if (kind == "umlXhost") return
	if (kind == "umlplutotest") return
	if (kind == "kvpllutotest") return

	var statuses_seen = kinds_seen[kind]
	var statuses_columns = []
	statuses_columns.title = kind
	columns.push(statuses_columns);

	lsw_filter_first_list(["good", "wip"], statuses_seen).forEach(function(status) {

	    // XXX: Exclude some historic status values since they are
	    // no longer used and just waste space.
	    if (status == "bad") return
	    if (status == "skiptest") return
	    if (status == "goos") return

	    var results_seen = statuses_seen[status]
	    var results_columns = []
	    results_columns.title = status
	    statuses_columns.push(results_columns);

	    lsw_filter_first_list(["passed", "failed"], results_seen).forEach(function(result) {
		result_column = {
		    title: {
			"passed": "pass",
			"failed": "fail",
			"unresolved": "not<br>resolved",
			"untested": "not<br>tested",
		    }[result] || result,
		    kind: kind,
		    status: status,
		    result: result,
		    value: function(test_run_row) {
			// field may be missing
			return test_run_row.totals &&
			    test_run_row.totals[this.kind] &&
			    test_run_row.totals[this.kind][this.status] &&
			    test_run_row.totals[this.kind][this.status][this.result] ||
			    ""
		    },
		}
		results_columns.push(result_column)
	    })
	})
    })

    //
    // Add an untested column.
    //
    // Need to compute it from the totals table
    //
    // XXX: should this and similar code in the graph table be merged?
    // Perhaps, but they are not that similar.
    //
    // XXX: Strictly speaking, an entry such as status=good
    // result=untested will be double counted (both below and above).
    // Fortunately, this "should never happen" - all status=good tests
    // should have been tested (if it does something bad happened and
    // the test run can be discarded).

    summary.test_runs.forEach(function(test_run) {
	test_run.untested = 0
	if (!test_run.totals) {
	    return
	}
	Object.keys(test_run.totals).forEach(function(kind) {
	    var kind_totals = test_run.totals[kind]
	    Object.keys(kind_totals).forEach(function(status) {
		var status_totals = kind_totals[status]
		if (status_totals.untested) {
		    test_run.untested += status_totals.untested
		}
	    })
	})
    })

    columns.push({
	title: "Untested",
    })

    //
    // Add the totals column
    //

    columns.push({
	title: "Total",
    })

    //
    // Add the error column
    //
    // For the moment just list the interesting (uppercase) errors,
    // add them, broken down, under an errors column.
    //
    // XXX: The errors should be broken down further into "good" and
    // "wip" but that data isn't available.
    //

    columns.push({
	title: "Errors",
	value: function(test_run) {
	    return lsw_errors_html(test_run.errors)
	},
    })

    // Add Extra info columns

    columns.push({
	title: "Start",
	html: function(row) {
	    return (row.start_time
		    ? lsw_date2iso(row.start_time)
		    : "")
	},
	value: function(row) {
	    return (row.start_time
		    ? row.start_time
		    : "")
	},
    })
    columns.push({
	title: "Time",
	value: function(row) {
	    return (row.runtime
		    ? row.runtime
		    : "")
	},
    })
    columns.push({
	title: "Directory",
	html: function(row) {
	    var a = ("<a href=\"" + row.directory + "\">"
		     + row.directory
		     + "</a>")
	    if (row == summary.current) {
		a += "<br/>" + summary.current.details
	    }
	    return a
	},
	value: function(row) {
	    return row.directory
	},
    })

    // Compute the body's rows

    lsw_table({
	id: table_id,
	data: summary.test_runs,
	sort: {
	    column: columns[0], // Commits
	    assending: false,
	},
	columns: columns,
	select: {
	    row: function(selected_test_runs) {
		lsw_compare_test_runs(selected_test_runs)
	    }
	},
    })
}


// Return a sorted list of MAP's keys, but with any key in FIRSTS
// moved to the front.
//
// For instance:
//
//    (["c", "d"], { "a", "b", "c" })
//    -> ["c", "a", "b"]

function lsw_filter_first_list(firsts, map) {
    // force firsts to the front
    var list = firsts.filter(function(first) {
	return first in map
    })
    // and then append any thing else in sort order
    Object.keys(map).sort().forEach(function(element) {
	if (list.indexOf(element) < 0) {
	    list.push(element)
	}
    })

    return list
}
