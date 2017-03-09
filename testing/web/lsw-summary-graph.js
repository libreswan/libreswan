
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
    // "untested"
]

function lsw_summary_graph(graph_id, table_id, summary) {

    // Only plot test_runs with a corresponding commit.

    var test_runs = summary.test_runs.filter(function(test_run) {
	return test_run.commit
    })

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
    // Create a dictionary of totals we're interested in.
    //
    var sums = {}
    test_runs.forEach(function(test_run) {
	var sum = []
	// Clean up the totals that we're interested in.  Add
	// accumulative (sums) and overall totals.
	var totals = test_run.totals
	var total = 0
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
	sums[test_run.commit.abbreviated_commit_hash] = sum
    })
    var sum_text = []
    var sum_klass = []
    lsw_status_names.forEach(function(status_name) {
	lsw_count_names.forEach(function(count_name) {
	    sum_text.push(status_name + ":" + count_name)
	    sum_klass.push(count_name)
	})
    })

    var x = d3.scaleTime()
	.domain([
	    d3.min(summary.commits, function(d) {
		return d.committer.date
	    }),
	    now,
	])
	.range([radius, width])
    var y = d3.scaleLinear()
	.domain([
	    d3.min(test_runs, function(d) {
		// very first accumulative value
		return 0.8 * sums[d.commit.abbreviated_commit_hash][0]
	    }),
	    d3.max(test_runs, function(d) {
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
    // Create a list of first-parent test_runs so that they can be
    // plotted as a line.
    //
    // Need to iterate through the commit parents[0] (first-parent)
    // entries to find them.  Since this is ordered new-to-old, the
    // first element is the right most.
    //

    var first_parent_test_runs = []
    for (var commit = summary.commits[0]; commit; commit = commit.parents[0]) {
	if (commit.test_run) {
	    first_parent_test_runs.push(commit.test_run)
	}
    }

    /*
     * Accumulate the key for each line.
     */
    var last_test_run = first_parent_test_runs[0]
    var keys_x = x(last_test_run.commit.committer.date) + radius
    var keys = []

    //
    // Plot thte grand total
    //
    // First as a line of trunk, and then as a scatter plot of all
    // test test_runs.
    svg.append("path")
	.datum(first_parent_test_runs)
	.attr("class", "line")
	.attr("d", d3.line()
	      .x(function(test_run) {
		  return x(test_run.commit.committer.date)
	      })
	      .y(function(test_run) {
		  return y(test_run.total)
	      }))
    svg.append("g")
	.selectAll(".dot")
	.data(test_runs)
	.enter()
	.append("circle")
	.attr("class", "untested")
	.attr("r", radius)
    	.attr("cx", function(test_run) {
	    return x(test_run.commit.committer.date)
	})
	.attr("cy", function(test_run) {
	    return y(test_run.total)
	})
	.on("click", function(test_run) {
	    lsw_summary_graph_click_test_run(table_id, test_run)
	})
	.append("title")
	.text(function(test_run) {
	    return lsw_commit_texts(test_run.commits)
	})
    keys.push({
	x: keys_x,
	y: y(last_test_run.total),
	klass: "untested",
	text: "+untested",
    })

    //
    // Plot the test test_runs proper
    //
    // First draw the line through the first parent of "good" test_runs;
    // but omit untested (should be zero).  And then overlay a scatter
    // plot of everything.
    for (var sum_index = sum_text.length - 1; sum_index >= 0; sum_index--) {
	var line = d3.line()
	    .x(function(test_run) {
		return x(test_run.commit.committer.date)
	    })
	    .y(function(test_run) {
		return y(sums[test_run.commit.abbreviated_commit_hash][sum_index])
	    })
	svg.append("path")
	    .datum(first_parent_test_runs)
	    .attr("class", "line")
	    .attr("d", line)
	svg.append("g")
	    .selectAll(".dot")
	    .data(test_runs)
	    .enter()
	    .append("circle")
	    .attr("class", sum_klass[sum_index])
	    .attr("r", radius)
	    .attr("cx", function(test_run) {
		return x(test_run.commit.committer.date)
	    })
	    .attr("cy", function(test_run) {
		return y(sums[test_run.commit.abbreviated_commit_hash][sum_index])
	    })
	    .on("click", function(test_run) {
		lsw_summary_graph_click_test_run(table_id, test_run)
		d3.event.stopPropagation()
	    })
	    .append("title")
	    .text(function(test_run) {
		return lsw_commit_texts(test_run.commits)
	    })
	keys.push({
	    x: keys_x,
	    y: y(sums[last_test_run.commit.abbreviated_commit_hash][sum_index]),
	    klass: sum_klass[sum_index],
	    text: (sum_index > 0 ? "+" : "") + sum_text[sum_index],
	})
    }

    //
    // Overlay the current commit dot.
    //
    if (summary.current.commits.length) {
	svg.append("g")
	    .selectAll(".dot")
	    .data([summary.current])
	    .enter()
	    .append("circle")
	    .attr("class", "current")
	    .attr("r", radius)
    	    .attr("cx", function(d) {
		return x(summary.current.commit.committer.date)
	    })
	    .attr("cy", function(d) {
		return height-radius
	    })
	    .append("title")
	    .text(function(d) {
		return (d.details
			+ "\nStarted: " + lsw_date2iso(new Date(d.start))
			+ "\nLast Update: " + lsw_date2iso(new Date(d.date))
			+ "\n" + lsw_commit_texts(summary.current.commits)

		       )
	    })
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
