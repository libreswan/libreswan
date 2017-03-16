// Callback with the loaded and cleaned up summary.json data set.

function lsw_summary_load(prefix, f) {
    d3.queue()
	.defer(d3.json, prefix + "summaries.json")
	.defer(d3.json, prefix + "commits.json")
	.defer(d3.json, prefix + "status.json")
	.awaitAll(function(error, results) {
	    if (error) {
		console.warn(error)
		return
	    }
	    var summary = {
		test_runs: results[0],
		commits: results[1],
		current: results[2],
	    }
	    lsw_summary_cleanup(summary)
	    f(summary)
	})
}

function lsw_summary_cleanup(summary) {

    // create a hash->commit lookup table so that hashes can be
    // converted to pointers.

    var commit_by_hash = []
    summary.commits.forEach(function (commit) {
	// create the lookup table
	var hash = commit.abbreviated_commit_hash
	commit_by_hash[hash] = commit
    })

    // Clean up 'current' (the status table); cross link current's
    // commit with current.

    summary.current.start = new Date(summary.current.start)
    summary.current.date = new Date(summary.current.date)
    if (summary.current.hash) {
	var commit = commit_by_hash[summary.current.hash]
	if (commit) {
	    summary.current.commit = commit
	    commit.current = summary.current
	}
    }

    // Clean up the commits

    summary.commits.forEach(function (commit) {
	// Fix values
	commit.author.date = new Date(commit.author.date)
	commit.committer.date = new Date(commit.committer.date)
	// Convert all commit parent hashes to pointers
	commit.parents = []
	commit.abbreviated_parent_hashes.forEach(function (parent_hash) {
	    var parent = commit_by_hash[parent_hash]
	    if (parent) {
		commit.parents.push(parent)
	    }
	})
    })

    // Clean up the result values; cross link with commits (when
    // possible).

    summary.test_runs.forEach(function (test_run) {
	// Clean up the contents
	test_run.start_time = new Date(test_run.start_time)
	test_run.end_time = new Date(test_run.end_time)
	// Try to cross link commit and test_run
	var hash = test_run.hash
	if (!hash) {
	    console.warn("missing hash for test_run", test_run)
	    return
	}
	// Cross link when possible.
	var commit = commit_by_hash[hash]
	if (!commit) {
	    console.warn("missing commit for test_run", test_run)
	    return
	}
	// Cross link commits and test_runs
	test_run.commit = commit
	commit.test_run = test_run
    })

    // Use the commit<->test_run links, along with commit.parents, to
    // Compute the list of commits that each test_run tested.
    //
    // What order should this be in?

    summary.test_runs.forEach(function(test_run) {
	test_run.commits = lsw_summary_commits(test_run.commit)
    })
    summary.current.commits = lsw_summary_commits(summary.current.commit)

}

function lsw_commit_texts(commits) {
    var subject = ""
    commits.forEach(function(commit) {
	subject = (subject
		   + lsw_date2iso(commit.committer.date)
		   + ": "
		   + commit.subject
		   + "\n")
    })
    return subject
}

// Use the commit<>test_run links and the commit.parents to identify all
// commits for a test_run.
function lsw_summary_commits(commit) {
    var commits = []
    if (commit) {
	commits.push(commit)
	var parents = commit.parents.slice()
	while (parents.length) {
	    var parent = parents.shift()
	    if (parent.test_run) {
		// stop when there is a test_run
		continue
	    }
	    if (commits.indexOf(parent) >= 0) {
		// stop if this is a duplicate (for instance two
		// branches joined).
		continue
	    }
	    commits.push(parent)
	    parents = parents.concat(parent.parents)
	}
    }
    return commits
}

// see http://stackoverflow.com/questions/24816/escaping-html-strings-with-jquery#12034334

var lsw_html_entity_map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;'
}

function lsw_html_escape(string) {
    return String(string).replace(/[&<>"'`=\/]/g, function (s) {
	return lsw_html_entity_map[s];
    })
}

// Convert commits to html

function lsw_commits_html(commits) {
    html = ""
    commits.forEach(function(commit) {
	html += lsw_date2iso(commit.committer.date)
	html += ": "
	html += "<a href=\""
	html += "https://github.com/libreswan/libreswan/commit/"
	html += commit.abbreviated_commit_hash
	html += "\">"
	html += commit.abbreviated_commit_hash
	html += "</a>"
	html += " "
	html += lsw_html_escape(commit.subject)
	html += "<br/>"
    })
    return html
}
