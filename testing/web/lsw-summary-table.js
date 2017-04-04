// lsw-summary-table.js

function lsw_summary_table(table_id, summary) {

    var now = new Date()

    var columns = [
	{
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
	    }
	},
	{
	    title: "Passed",
	},
	{
	    title: "Failed",
	},
	{
	    title: "Unresolved",
	},
	{
	    title: "Untested",
	},
	{
	    title: "Total",
	},
    ]

    // Add error columns.

    var errors = []
    summary.test_runs.forEach(function(test_run) {
	for (var error in test_run.errors) {
	    if (test_run.errors.hasOwnProperty(error)) {
		if (error == error.toUpperCase()) {
		    if (errors.indexOf(error) < 0) {
			errors.push(error)
		    }
		}
	    }
	}
    })
    errors.forEach(function(error) {
	columns.push({
	    title: error,
	    value: function(data) {
		return (data.errors && data.errors[error]
			? data.errors[error]
			: "")
	    },
	})
    })

    var suffix = [
	{
	    title: "Started",
	    html: function(row) {
		return (row.start_time
			? lsw_date2iso(row.start_time)
			: row.start
			? lsw_date2iso(row.start)
			: "")
	    },
	    value: function(row) {
		return (row.start_time
			? row.start_time
			: row.start
			? row.start
			: "")
	    },
	},
	{
	    title: "Time",
	    value: function(row) {
		return (row.runtime
			? row.runtime
			: "")
	    },
	},
	{
	    title: "Directory",
	    html: function(row) {
		if (row.directory) {
		    return ("<a href=\"" + row.directory + "\">"
			    + row.directory
			    + "</a>")
		} else {
		    return "<b>in progress</b>"
		}
	    },
	    value: function(row) {
		return (row.directory
			? row.directory
			: "")
	    },
	},
    ]
    suffix.forEach(function(column) {
	columns.push(column)
    })

    // Compute the body's rows

    lsw_table({
	id: table_id,
	data: (summary.current.commits.length
	       ? summary.test_runs.concat(summary.current)
	       : summary.test_runs),
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
