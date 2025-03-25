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

function lsw_summary_cleanup(status, commits, test_runs, current) {

    let summary = {}

    summary.status = new Status(status)

    // Clean up the commits.  Accumulate a table containing all the
    // commits.

    summary.commits = new Commits(commits)

    // Clean up the test_runs.

    console.log("raw test runs", test_runs)
    summary.test_runs = test_runs.filter((test_run, index) => {
	if (test_run.directory == status.directory) {
	    console.warn("discarding test run", test_run, "at", index, "that duplicates status.directory")
	    return false
	}
	// Check that the test run has a valid hash.
	let hash = test_run.hash
	if (!hash) {
	    console.warn("discarding test run", test_run, "at", index, "with a missing .hash")
	    return false
	}
	let commit = summary.commits.hash_to_commit[hash]
	if (!commit) {
	    console.warn("discarding test run", test_run, "at", index, "with no commit matching .hash")
	    return false
	}
	return true
    }).map((test_run) => {
	return new TestRun(test_run, summary.commits.hash_to_commit)
    })

    // Create "summary.current" and append it to test_runs

    if (current && current.hash in summary.commits.hash_to_commit) {
	console.log("current from current")
	summary.current = new TestRun(current, summary.commits.hash_to_commit)
	summary.test_runs.push(summary.current)
    }

    // Create a dictionary of directory->test_run so that
    // ?run=<directory> can find them.

    summary.test_run_by_directory = []
    for (const test_run of summary.test_runs) {
	summary.test_run_by_directory[test_run.directory] = test_run
    }

    // Use the commit<->test_run and commit.parent[] links created
    // above to find the commits unique to this test run.  Cross
    // link those additional commits back to the test.
    for (const test_run of summary.test_runs) {
	lsw_summary_commits(test_run)
    }

    // Sort the test run by commits topologically in ascending order.

    summary.test_runs.sort((l, r) => {
	return l.commit.rank - r.commit.rank
    })

    console.log("cooked test runs", summary.test_runs)

    return summary
}

function lsw_commit_texts(commits) {
    let subject = ""
    for (const commit of commits) {
	subject = (subject
		   + lsw_date2iso(commit.author_date)
		   + ": "
		   + commit.subject
		   + "\n")
    }
    return subject
}

// Use the commit<>test_run links and the commit.parents to identify
// all commits for a test_run.

function lsw_summary_commits(test_run) {
    test_run.commits = []
    test_run.commits.push(test_run.commit)
    let parents = test_run.commit.parents.slice()
    while (parents.length) {
	let parent = parents.shift()
	if (parent.test_run) {
	    // stop when there is a test_run
	    continue
	}
	if (test_run.commits.includes(parent)) {
	    // don't process things twice
	    continue;
	}
	// back link this commit to the same test, acts as a loop
	// sentinel.
	// parent.test_run = test_run
	test_run.commits.push(parent)
	parents = parents.concat(parent.parents)
    }
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
