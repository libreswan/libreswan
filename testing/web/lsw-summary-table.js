// lsw-summary-table.js

function lsw_summary_table(table_id, summary) {

    let now = new Date()

    let columns = []

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
    // The table "totals" is structured:
    //
    //    <kind> . <status> . <result|errors> . <count>
    //
    // and the table reflects this (with some filtering).

    for (const kind of ["kvmplutotest"]) {

	let statuses_columns = []
	statuses_columns.title = kind
	columns.push(statuses_columns);

	for (const status of ["good", "wip"]) {

	    let results_columns = []
	    results_columns.title = status
	    statuses_columns.push(results_columns)

	    for (const result of ["passed", "failed", "unresolved", "untested"]) {
		// map result onto its title
		const title = {
		    "passed": "pass",
		    "failed": "fail",
		    "unresolved": "not<br>resolved",
		    "untested": "not<br>tested",
		}[result] || result
		result_column = {
		    title: title,
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
	    }
	    results_columns.push({
		title: "errors",
		value: function(test_run) {
		    return lsw_errors_html(test_run.errors)
		},
	    })
	}
    }

    //
    // Add the totals column
    //

    columns.push({
	title: "Total",
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
	    let a = ("<a href=\"" + row.directory + "\">"
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
    let list = firsts.filter(function(first) {
	return first in map
    })
    // and then append any thing else in sort order
    for (const element of Object.keys(map).sort()) {
	if (list.indexOf(element) < 0) {
	    list.push(element)
	}
    }

    return list
}
