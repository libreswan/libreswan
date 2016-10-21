var summary_titles =  [
    "Date", "Commit",
    "Pass", "Fail", "Unresolved", "Untested", "Total",
    "Started", "Time",
    "Directory",
    "<commit>", "<result>",
]
var summary_subject_col = 1
var summary_directory_col = 9
var summary_commit_col = 10
var summary_result_col = 11

function summary_table(div_id, summary) {

    // Merge results and untested commits.
    var values = []

    // Add all the result entries.
    summary.results.forEach(function(d) {
	values.push([
	    lsw_date2iso(d.commit.committer_date),
	    d.commit.subject,
	    d.passed,
	    d.failed,
	    d.unresolved,
	    d.untested,
	    d.total,
	    lsw_date2iso(d.start_time),
	    d.runtime,
	    d.directory,
	    d.commit,
	    d,
	])
    })

    // Add all the untested commit entries
    summary.untested_interesting_commits.forEach(function(d) {
	values.push([
	    lsw_date2iso(d.committer_date),
	    d.subject,
	    "", // passed
	    "", // failed
	    "", // unresolved
	    "", // untested
	    "", // total
	    "", // start_time
	    "", // runtime
	    "", // directory
	    d,
	    null,
	])
    })

    // Add the current commit entry.
    if (summary.current_commit) {
	values.push([
	    lsw_date2iso(summary.current_commit.committer_date),
	    summary.current_commit.subject,
	    "", // passed
	    "", // failed
	    "", // unresolved
	    "", // untested
	    "", // total
	    lsw_date2iso(summary.status.start), // start_time
	    "", // runtime
	    "", // directory
	    summary.current_commit,
	    null,
	])
    }

    // Sort in reverse date order - so most recent is at the top.
    // Column 0, the date, has been converted to an ISO string.
    values.sort(function(l, r) {
	return r[0].localeCompare(l[0])
    })

    // Init Tidy-Table
    document.getElementById(div_id)
	.TidyTable({
            enableCheckbox : false,
            enableMenu     : false,
	}, {
            columnTitles : summary_titles,
            columnValues : values,
	    postProcess: {
		table: function(table) {
		    fixup_summary_table(table, values)
		}
	    },
	})
}

function fixup_summary_table(table, values) {
    var cols

    // Hide the <commit> column
    var commit_col = summary_commit_col + 1
    cols = table.querySelectorAll("th:nth-child(" + commit_col + "), td:nth-child(" + commit_col + ")");
    for (var i = 0; i < cols.length; i++) {
	cols[i].style.display = "none";
    }
    // Hide the <result> column
    var result_col = summary_result_col + 1
    cols = table.querySelectorAll("th:nth-child(" + result_col + "), td:nth-child(" + result_col + ")");
    for (var i = 0; i < cols.length; i++) {
	cols[i].style.display = "none";
    }

    // Point the directory column at the test directory
    cols = table.querySelectorAll("td:nth-child(" + (summary_directory_col + 1) + ")");
    for (var i = 0; i < cols.length; i++) {
	var col = cols[i]
	var child = col.childNodes[0]
	var text = child.data
	var result = values[i][summary_result_col]
	if (result) {
	    var a = document.createElement("a")
	    a.setAttribute("href", result.directory)
	    a.appendChild(document.createTextNode(text))
	    col.replaceChild(a, child)
	}
    }

    // Point the subject column at the git hub commit
    cols = table.querySelectorAll("td:nth-child(" + (summary_subject_col + 1) + ")");
    for (var i = 0; i < cols.length; i++) {
	var col = cols[i]
	var child = col.childNodes[0]
	var text = child.data
	var commit = values[i][summary_commit_col]
	var a = document.createElement("a")
	var href = "https://github.com/libreswan/libreswan/commit/" + commit.abbreviated_commit_hash
	a.setAttribute("href", href)
	// HACK
	var trunc = 60
	if (text.length > trunc) {
	    text = text.substr(0, trunc - 3) + "..."
	}
	var new_text = document.createTextNode(text)
	new_text
	a.appendChild(new_text)
	col.replaceChild(a, child)
    }
}
