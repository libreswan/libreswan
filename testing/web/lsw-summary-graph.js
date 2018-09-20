
var lsw_kind_names = [
    "kvmplutotest",
]

var lsw_status_names = [
    "good",
    "wip",
]

var lsw_count_names = [
    "passed",
    "failed",
    "unresolved",
    // "untested" gets pooled at the top as "total"
]

function lsw_summary_graph(graph_id, table_id, summary) {

    console.log("test_runs:", summary.test_runs.length)

    // old code; don't plot nothing
    if (summary.test_runs.length == 0) {
	console.log("nothing to graph")
	return
    }

    var margin = {
	top: 10,
	right: 90,
	bottom: 30,
	left: 50
    }
    var width = 960 - margin.left - margin.right
    var height = 500 - margin.top - margin.bottom
    var radius = 3.0

    var now = new Date()

    //
    // Split the results into "full" (has at least some real data) and
    // "empty" (no data to talk of)
    //
    var empty_test_runs = []
    var full_test_runs = []
    summary.test_runs.forEach(function(test_run) {
	// Drop anything that doesn't have a result.
	if (test_run.totals) {
	    full_test_runs.push(test_run)
	    // Current is always added to "empty" so it appears on the
	    // bottom line.
	    if (test_run == summary.current) {
		empty_test_runs.push(test_run)
	    }
	} else {
	    empty_test_runs.push(test_run)
	}
    })
    console.log("empty_test_runs:", empty_test_runs.length)
    console.log("full_test_runs:", full_test_runs.length)

    //
    // Create "sums[HASH][]" sub-tables of running totals for each "full"
    // test_run.  The running total's title and class can be found in
    // the corresponding sum_text[] and sum_klass[] table entries.
    //

    var sum_text = []
    var sum_klass = []
    lsw_status_names.forEach(function(status_name) {
	lsw_count_names.forEach(function(count_name) {
	    // all but first have "+" prepended
	    sum_text.push((sum_text.length ? "+" : "") + status_name + ":" + count_name)
	    sum_klass.push(count_name)
	})
    })
    sum_text.push("+untested")
    sum_klass.push("untested")

    var sums = {}
    full_test_runs.forEach(function(test_run) {
	var totals = test_run.totals
	// Tally up the totals that we're interested in.
	var total = 0
	var sum = []
	lsw_kind_names.forEach(function(kind_name) {
	    var kind = (totals.hasOwnProperty(kind_name)
			? totals[kind_name]
			: {})
	    lsw_status_names.forEach(function(status_name) {
		var status = (kind.hasOwnProperty(status_name)
			      ? kind[status_name]
			      : {})
		lsw_count_names.forEach(function(count_name) {
		    var count = (status.hasOwnProperty(count_name)
				 ? status[count_name]
				 : 0)
		    total += count
		    sum.push(total)
		})
	    })
	})
	// finally grand total as "untested"
	sum.push(test_run.total)
	sums[test_run.commit.hash] = sum
    })

    //
    // Set up the graph dimensions and scale
    //
    // Use first test run's committer.date (test runs are ordered by
    // that dated).

    var start = summary.test_runs[0].commit.committer.date
    console.log("graph start:", start)

    var xt = d3.scaleUtc()
	.domain([start, now])
	.range([1, width])
    var xp = d3.scalePow()
	.exponent(2)
	.domain([1, width])
	.range([0, width])

    // Fool d3js into thinking that it is looking at a scale object.
    function x_copy() {
	var x = function(t) { return xp(xt(t)) }
	x.domain = xt.domain
	x.range = xp.range
	x.copy = x_copy
	x.tickFormat = xt.tickFormat
	x.ticks = xt.ticks
	return x
    }
    x = x_copy()

    // set the graph size based on results with "full" data
    var y = d3.scaleLinear()
	.domain([
	    d3.min(full_test_runs, function(d) {
		// very first accumulative value
		return 0.8 * sums[d.commit.hash][0]
	    }),
	    d3.max(full_test_runs, function(d) {
		return 1.02 * d.total
	    })
	])
	.range([height, 0])

    var xAxis = d3.axisBottom(x)
    var yAxis = d3.axisLeft(y)

    var svg = d3.select("#" + graph_id)
	.insert("svg")
	.attr("width", width + margin.left + margin.right)
	.attr("height", height + margin.top + margin.bottom)
	.append("g")
	.attr("transform", "translate(" + margin.left + "," + margin.top + ")")

    // X-axis
    svg.append("g")
	.attr("class", "x axis")
	.attr("transform", "translate(0," + height + ")")
	.call(xAxis)

    // Y-axis
    svg.append("g")
	.attr("class", "y axis")
	.call(yAxis)
	.append("text")
	.attr("transform", "rotate(-90)")
	.attr("y", 6)
	.attr("dy", ".71em")
	.style("text-anchor", "end")
	.text("Results")

    //
    // Accumulate a legend (keys, label) array
    //
    // Each entry is positioned beyond the last test run (good or
    // bad).
    //

    var newest_test_run = summary.test_runs[summary.test_runs.length - 1]
    console.log("newest_test_run", newest_test_run)
    var keys_x = x(newest_test_run.commit.committer.date) + radius
    var keys = []

    //
    // The graph has two right-hand-side ends, the last "full" result
    // and the last result (the latter may have no actual results).
    //

    //
    // Create a list of "full" first-parent test_runs so that they can
    // be plotted as a line.  (i.e., first parents that have a proper
    // result).
    //
    // Since commits are not ordered use the commit from the the most
    // recent test run as the starting point.  Need to also exclude
    // current as its results are meaningless.
    //
    // Since this follows parent (older) links and appends entries,
    // the result is in reverse cronological order.

    var good_first_parent_test_runs = []
    for (var commit = newest_test_run && newest_test_run.commit;
	 commit; commit = commit.parents[0]) {
	if (commit.test_run && commit.test_run.totals && commit.test_run != summary.current) {
	    good_first_parent_test_runs.push(commit.test_run)
	}
    }
    console.log("good_first_parent_test_runs:", good_first_parent_test_runs.length)

    //
    // Identify the right-most side of the "full" plot.
    //
    // Things like keys are positioned based on this.  Remember,
    // good_first_parent_test_runs[] is in reverse cronological order
    // so "last" is at the front.

    var newest_first_parent_test_run = good_first_parent_test_runs[0]
    console.log("newest_first_parent_test_run:", newest_first_parent_test_run)

    //
    // Plot the full test runs proper
    //
    // First draw the line through the first parent then overlay a
    // scatter plot of everything.

    for (var sum_index = sum_text.length - 1; sum_index >= 0; sum_index--) {
	var line = d3.line()
	    .x(function(test_run) {
		return x(test_run.commit.committer.date)
	    })
	    .y(function(test_run) {
		return y(sums[test_run.commit.hash][sum_index])
	    })
	svg.append("path")
	    .datum(good_first_parent_test_runs)
	    .attr("class", "line")
	    .attr("d", line)
	svg.append("g")
	    .attr("class", sum_klass[sum_index])
	    .selectAll(".dot")
	    .data(full_test_runs)
	    .enter()
	    .append("circle")
	    .attr("class", function(test_run) {
		if (test_run == summary.current) {
		    return "current"
		} else {
		    return "full" // vs empty
		}
	    })
	    .attr("r", radius)
	    .attr("cx", function(test_run) {
		return x(test_run.commit.committer.date)
	    })
	    .attr("cy", function(test_run) {
		return y(sums[test_run.commit.hash][sum_index])
	    })
	    .on("click", function(test_run) {
		lsw_summary_graph_click_test_run(table_id, test_run)
		d3.event.stopPropagation()
	    })
	    .append("title")
	    .text(function(test_run) {
		return (test_run == summary.current
			? ("In progress: " + test_run.details
			   + "\nLast Update: " + lsw_date2iso(test_run.date)
			   + "\n")
			: "") + lsw_commit_texts(test_run.commits)
	    })
	if (newest_first_parent_test_run) {
	    keys.push({
		x: keys_x,
		y: y(sums[newest_first_parent_test_run.commit.hash][sum_index]),
		klass: sum_klass[sum_index],
		text: sum_text[sum_index],
	    })
	}
    }

    //
    // Overlay the bad test runs
    //
    svg.append("g")
	.attr("class", "empty")
	.selectAll(".dot")
	.data(empty_test_runs)
	.enter()
	.append("circle")
	.attr("class", function(test_run) {
	    if (test_run == summary.current) {
		return "current"
	    } else {
		return "empty"
	    }
	})
	.attr("r", radius)
	.attr("cx", function(test_run) {
	    return x(test_run.commit.committer.date)
	})
	.attr("cy", function(test_run) {
	    return height-radius
	})
	.append("title")
	.text(function(test_run) {
	    return (test_run == summary.current
		    ? (test_run.details
		       + (test_run.date ? ("\nLast Update: " + lsw_date2iso(test_run.date)) : "")
		       + "\n")
		    : "") + lsw_commit_texts(test_run.commits)
	})

    //
    // Overlay the current commit dot.
    //
    if (summary.current.commits && summary.current.commits.length) {
	keys.push({
	    klass: "current",
	    x: x(summary.current.commit.committer.date) + radius,
	    y: height - radius,
	    text: "Current",
	})
    }

    //
    // Titles for the mess
    //
    var enter_keys = svg
	.selectAll(".key")
	.data(keys)
	.enter()
	.append("text")
	.attr("class", function(d) {
	    return d.klass
	})
	.text(function(d) {
	    return d.text
	})
	.attr("x", function(d) {
	    return d.x
	})
	.attr("y", function(d) {
	    return d.y
	})

}
