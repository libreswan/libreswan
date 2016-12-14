// lsw-summary-table.js

function lsw_summary_table(table_id, summary) {

    var columns = [
	{
	    title: "Commits",
	    html: function(row) {
		return lsw_commits_html(row.commits)
	    },
	    value: function(row) {
		return row.commits[0].committer_date
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
    summary.results.forEach(function(result) {
	for (var error in result.errors) {
	    if (result.errors.hasOwnProperty(error)) {
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
	       ? summary.results.concat(summary.current)
	       : summary.results),
	sort: {
	    column: columns[0], // Commits
	    assending: false,
	},
	columns: columns,
	select: {
	    row: function(results_summaries) {
		lsw_compare_summary(results_summaries)
	    }
	},
    })
}
