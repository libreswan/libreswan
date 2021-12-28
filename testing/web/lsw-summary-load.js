// Callback with the loaded and cleaned up summary.json data set.

function lsw_safe_load(query, path, callback)  {
    // wrap the d3.queue() "callback" function with our custom version
    // that discards a 404 (not found) error that might bubble up from
    // d3.json().
    return d3.json(path, function(error, json) {
	if (error) {
	    if (error.target && error.target.status == 404) {
		console.log("ignoring not-found", error)
		return callback(null, null)
	    } else {
		console.log("fetching failed", error)
		return callback(error)
	    }
	} else {
	    return callback(null, json)
	}
    })
}

function lsw_directory_hash(path) {
    if (!path) {
	return undefined
    }
    let npath = path.replace(/.*-g([^-]*)-.*/, "$1")
    if (npath == path) {
	return undefined
    }
    return npath
}

function lsw_summary_load(prefix, f) {
    let now = Date()
    let q = d3.queue()
    q.defer(d3.json, prefix + "status.json?" + now)
    q.await(function(error, status) {
	if (error) {
	    console.warn("fetching status failed", error)
	    return
	}
	console.log("status:", status)

	// Generate a tag for fetching big stuff that changes once
	// per-directory.
	let tag = "?"
	if (status) {
	    if (status.directory) {
		// a current directory, assume commits.json was
		// updated when the directory was started.
		tag += status.directory
	    } else {
		// no current directory, assume things are idle and
		// won't be updated until at least the next status
		// update.
		tag += status.date
	    }
	} else {
	    // no status, be conservative and force an update using
	    // the date.
	    tag += now
	}

	// pull in the commits and subdirectories.
	let q = d3.queue()
	q.defer(d3.json, prefix + "commits.json" + tag)
	q.defer(d3.json, prefix + "summaries.json" + tag)
	// also fetch the current directory's summary; it might not be
	// present
	if (status.directory && status.directory.length) {
	    q.defer(lsw_safe_load, d3.json, prefix + status.directory + "/summary.json?" + now)
	}
	q.await(function(error, commits, summaries, current) {
	    if (error) {
		console.warn("fetching commits/summaries failed", error)
		return
	    }
	    console.log("commits:", commits.length)
	    console.log("summaries:", summaries.length)
	    console.log("current:", current)

	    let summary = lsw_summary_cleanup(status, commits, summaries, current)
	    f(summary)
	})
    })
}

function lsw_summary_cleanup(status, commits, summaries, current) {


    let summary = {}

    // Create "summary.current" by merging current into status.

    summary.current = status
    if (current) {
	for (const key of Object.keys(current)) {
	    status[key] = current[key]
	}
    }
    // probably redundant; but easier
    lsw_cleanup_dates(summary.current, ["date"])
    console.log("summary.current", summary.current)

    // Clean up the commits discarding anything strange.  Accumulate a
    // table containing all the commits.

    let commit_by_hash = []
    summary.commits = commits.filter(function (commit) {
	// Fix values
	if (!lsw_cleanup_dates(commit.author, ["date"])) {
	    console.log("discarding commit with no author date", commit)
	    return false
	}
	if (!lsw_cleanup_dates(commit.committer, ["date"])) {
	    console.log("discarding commit with no committer date", commit)
	    return false
	}
	// add to the lookup table
	let hash = commit.hash
	if (!hash) {
	    console.log("discarding commit with no hash", commit)
	    return false
	}
	if (commit_by_hash[hash]) {
	    console.log("discarding duplicate commit", commit)
	    return false
	}
	commit_by_hash[hash] = commit
	// other fields; see below
	commit.children = []
	commit.parents = []
	return true
    })

    // Using the above hash->commit table, fill in the .parent[] and
    // .children[] fields from the relevant hashes.

    for (const commit of summary.commits) {
	for (parent_hash of commit.parent_hashes) {
	    let parent = commit_by_hash[parent_hash]
	    if (parent) {
		// cross link the parent and child
		commit.parents.push(parent)
		parent.children.push(commit)
	    }
	}
    }

    // Clean up the result values discarding anything strange.
    //
    // Use the hash table above to cross link each test run with a
    // corresponding commit.
    //
    // Ensure the summary for current is up-to-date by appending the
    // latest and discarding any older earlier entry.

    if (current) {
	summaries.push(summary.current)
    }
    summary.test_runs = summaries.filter(function(test_run, index) {
	// The above appended current's summary on the end so anything
	// earlier is an out-of-date duplicate.
	if (index < summaries.length - 1 && status.directory == test_run.directory) {
	    console.warn("discarding test run", test_run, "at", index, "duplicating current")
	    return false
	}
	// Validate the contents
	if (!lsw_cleanup_dates(test_run, ["start_time", "stop_time"])) {
	    console.warn("discarding test run", test_run, "at", index, "with invalid dates")
	    return false
	}
	// Try to cross link commit and test_run
	let hash = test_run.hash
	if (!hash) {
	    console.warn("discarding test run", test_run, "at", index, "with a missing .hash")
	    return false
	}
	// Cross link when possible.
	let commit = commit_by_hash[hash]
	if (!commit) {
	    console.warn("discarding test run", test_run, "at", index, "with commit matching .hash")
	    return false
	}
	// Cross link commits and test_runs
	test_run.commit = commit
	commit.test_run = test_run
	return true
    })

    // Sort the test run by committer.date in ascending order.

    summary.test_runs.sort(function(l, r) {
	return l.commit.committer.date - r.commit.committer.date
    })

    summary.test_run_by_directory = []
    for (const test_run of summary.test_runs) {

	// Create a dictionary of directory->test_run so that
	// ?run=<directory> can find them

	summary.test_run_by_directory[test_run.directory] = test_run

	// Use the commit<->test_run and commit.parent[] links created
	// above to find the commits unique to this test run.  Cross
	// link those additional commits back to the test.

	test_run.commits = lsw_summary_commits(test_run.commit)
	for (const commit of test_run.commits) {
	    // One of these assignments is redundant, oops.
	    commit.test_run = test_run;
	}
    }

    return summary
}

function lsw_commit_texts(commits) {
    let subject = ""
    for (const commit of commits) {
	subject = (subject
		   + lsw_date2iso(commit.committer.date)
		   + ": "
		   + commit.subject
		   + "\n")
    }
    return subject
}

// Use the commit<>test_run links and the commit.parents to identify
// all commits for a test_run.

function lsw_summary_commits(commit) {
    let commits = []
    if (commit) {
	commits.push(commit)
	let parents = commit.parents.slice()
	while (parents.length) {
	    let parent = parents.shift()
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
    // Return the list in reverse commit-date order.
    return commits.sort(function(l, r) {
	return r.committer.date - l.committer.date
    })
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

// Return the commits as a blob of HTML.

var lsw_abbrev_hash_length = 9

function lsw_commits_html(commits) {
    html = ""
    html += "<table class=\"commits\"><tbody class=\"commits\">"
    for (const commit of commits) {
	html += "<tr class=\"" + commit.interesting + "\" title=\"interesting commit: " + commit.interesting + "\">"
	html += "<td class=\"date\">"
	html += lsw_date2iso(commit.committer.date)
	html += ":</td>"
	html += "<td class=\"hash\">"
	html += "<a href=\""
	html += "https://github.com/libreswan/libreswan/commit/"
	html += commit.hash
	html += "\">"
	html += commit.hash.substring(0, lsw_abbrev_hash_length);
	html += "</a>"
	html += "</td>"
	html += "<td class=\"subject\">"
	html += lsw_html_escape(commit.subject)
	html += "</td>"
	html += "</tr>"
    }
    html += "</tbody></table>"
    return html
}
