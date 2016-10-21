// Callback with the loaded and cleaned up summary.json data set.

var lsw_result_names = [
    "passed",
    "failed",
    "unresolved",
    "untested"
]

function lsw_load_summary(prefix, f) {
    d3.queue()
	.defer(d3.json, prefix + "summaries.json")
	.defer(d3.json, prefix + "commits.json")
	.defer(d3.json, prefix + "status.json")
	.awaitAll(function(error, results) {
	    if (error) {
		console.log(error)
		return
	    }
	    var summary = {
		raw_results: results[0],
		commits: results[1],
		status: results[2],
	    }
	    lsw_cleanup_summary(summary)
	    f(summary)
	})
}

function lsw_cleanup_summary(summary) {

    // Clean up the commits, creating a lookup-by-hash table.

    summary.commit_by_hash = []
    summary.commits.forEach(function (commit) {
	var hash = commit.abbreviated_commit_hash
	commit.author_date = new Date(commit.author_date)
	commit.committer_date = new Date(commit.committer_date)
	// Add to the hash table
	summary.commit_by_hash[hash] = commit
    })

    // Clean up the results, creating a lookup-by-hash table.  Filter
    // out any results that don't have a corresponding commit.

    summary.result_by_hash = []
    summary.results = []
    summary.raw_results.forEach(function (result) {
	var hash = result.directory.match(/.*-g([^-]*)-*/)[1]
	var commit = summary.commit_by_hash[hash]
	if (!commit) {
	    console.log("missing commit for result", result)
	    return
	}
	// Clean up the summary
	result.start_time = new Date(result.start_time)
	result.commit = commit
	// accumulate results
	result.results = []
	result.totals = [0]
	var total = 0
	lsw_result_names.forEach(function(name) {
	    var count = (result.hasOwnProperty(name)
			  ? +result[name]
			  : 0)
	    total += count
	    result.results.push(count)
	    result.totals.push(total)
	})
	// add to the hash table
	summary.result_by_hash[hash] = result
	summary.results.push(result)
    })

    // Clean up the status table

    summary.status.start = new Date(summary.status.start)
    summary.status.date = new Date(summary.status.date)

    // Create a list of first-parent results ordered oldest to
    // youngest.  This way more recent commits are on top.
    //
    // Need to iterate through the commit parents[0] (first-parent)
    // entries to find them.

    summary.first_parent_results = []
    var hash = summary.commits[0].abbreviated_commit_hash
    while (true) {
	if (!hash) break;
	var commit = summary.commit_by_hash[hash]
	if (!commit) break;
	var result = summary.result_by_hash[hash]
	if (result) {
	    summary.first_parent_results.push(result)
	}
	hash = commit.abbreviated_parent_hashes[0]
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
	if (summary.result_by_hash[commit.abbreviated_commit_hash]) {
	    return
	}
	if (summary.status.hash == commit.abbreviated_commit_hash) {
	    return
	}
	summary.untested_interesting_commits.push(commit)
    })
    summary.untested_interesting_commits.reverse()

    summary.current_commit = summary.commit_by_hash[summary.status.hash]
}
