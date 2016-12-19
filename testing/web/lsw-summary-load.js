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
		results: results[0],
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
	commit.author_date = new Date(commit.author_date)
	commit.committer_date = new Date(commit.committer_date)
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

    summary.results.forEach(function (result) {
	// Clean up the contents
	result.start_time = new Date(result.start_time)
	result.end_time = new Date(result.end_time)
	// Try to cross link commit and result
	var hash = result.hash
	if (!hash) {
	    console.warn("missing hash for result", result)
	    return
	}
	// Cross link when possible.
	var commit = commit_by_hash[hash]
	if (!commit) {
	    console.warn("missing commit for result", result)
	    return
	}
	// Cross link commits and results
	result.commit = commit
	commit.result = result
    })

    // Use the commit<->result links, along with commit.parents, to
    // Compute the list of commits that each result tested.
    //
    // What order should this be in?

    summary.results.forEach(function(result) {
	result.commits = lsw_summary_commits(result.commit)
    })
    summary.current.commits = lsw_summary_commits(summary.current.commit)

    // Create a list of first-parent results ordered oldest to
    // youngest.  This way more recent commits are on top.
    //
    // Need to iterate through the commit parents[0] (first-parent)
    // entries to find them.

    summary.first_parent_results = []
    for (var commit = summary.commits[0]; commit; commit = commit.parents[0]) {
	if (commit.result) {
	    summary.first_parent_results.push(commit.result)
	}
    }
    // oldest first
    summary.first_parent_results.reverse()

    // List of commits that are inline to be tested, order them oldest
    // to youngest so that, when graphed, more recent commits are on
    // top.

    summary.untested_interesting_commits = []
    summary.commits.forEach(function(commit) {
	if (!commit.interesting) {
	    return
	}
	if (commit.result) {
	    return
	}
	if (summary.current.commit == commit) {
	    return
	}
	summary.untested_interesting_commits.push(commit)
    })
    summary.untested_interesting_commits.reverse()

}

function lsw_commit_texts(commits) {
    var subject = ""
    commits.forEach(function(commit) {
	subject = (subject
		   + lsw_date2iso(commit.committer_date)
		   + ": "
		   + commit.subject
		   + "\n")
    })
    return subject
}

// Use the commit<>result links and the commit.parents to identify all
// commits for a result.
function lsw_summary_commits(commit) {
    var commits = []
    if (commit) {
	commits.push(commit)
	var parents = commit.parents.slice()
	while (parents.length) {
	    var parent = parents.shift()
	    if (parent.result) {
		// stop when there is a result
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

// Convert commits to html

function lsw_commits_html(commits) {
    html = ""
    commits.forEach(function(commit) {
	html += lsw_date2iso(commit.committer_date)
	html += ": "
	html += "<a href=\""
	html += "https://github.com/libreswan/libreswan/commit/"
	html += commit.abbreviated_commit_hash
	html += "\">"
	html += commit.abbreviated_commit_hash
	html += "</a>"
	html += " "
	html += commit.subject
	html += "<br/>"
    })
    return html
}
