
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

    // Only plot results with a corresponding commit.

    var results = summary.results.filter(function(result) {
	return result.commit
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
    results.forEach(function(result) {
	var sum = []
	// Clean up the totals that we're interested in.  Add
	// accumulative (sums) and overall totals.
	var totals = result.totals
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
	sums[result.commit.abbreviated_commit_hash] = sum
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
		return d.committer_date
	    }),
	    now,
	])
	.range([radius, width])
    var y = d3.scaleLinear()
	.domain([
	    d3.min(results, function(d) {
		// very first accumulative value
		return 0.8 * sums[d.commit.abbreviated_commit_hash][0]
	    }),
	    d3.max(results, function(d) {
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

    /*
     * Accumulate the key for each line.
     */
    var last_result = summary.first_parent_results[summary.first_parent_results.length - 1]
    var keys_x = x(last_result.commit.committer_date) + radius
    var keys = []

    //
    // Plot thte grand total
    //
    // First as a line of trunk, and then as a scatter plot of all
    // test results.
    svg.append("path")
	.datum(summary.first_parent_results)
	.attr("class", "line")
	.attr("d", d3.line()
	      .x(function(result) {
		  return x(result.commit.committer_date)
	      })
	      .y(function(result) {
		  return y(result.total)
	      }))
    svg.append("g")
	.selectAll(".dot")
	.data(results)
	.enter()
	.append("circle")
	.attr("class", "untested")
	.attr("r", radius)
    	.attr("cx", function(result) {
	    return x(result.commit.committer_date)
	})
	.attr("cy", function(result) {
	    return y(result.total)
	})
	.on("click", function(result) {
	    lsw_summary_graph_click_result(table_id, result)
	})
	.append("title")
	.text(function(result) {
	    return lsw_commit_texts(result.commits)
	})
    keys.push({
	x: keys_x,
	y: y(last_result.total),
	klass: "untested",
	text: "+untested",
    })

    //
    // Plot the test results proper
    //
    // First draw the line through the first parent of "good" results;
    // but omit untested (should be zero).  And then overlay a scatter
    // plot of everything.
    for (var sum_index = sum_text.length - 1; sum_index >= 0; sum_index--) {
	var line = d3.line()
	    .x(function(result) {
		return x(result.commit.committer_date)
	    })
	    .y(function(result) {
		return y(sums[result.commit.abbreviated_commit_hash][sum_index])
	    })
	svg.append("path")
	    .datum(summary.first_parent_results)
	    .attr("class", "line")
	    .attr("d", line)
	svg.append("g")
	    .selectAll(".dot")
	    .data(results)
	    .enter()
	    .append("circle")
	    .attr("class", sum_klass[sum_index])
	    .attr("r", radius)
	    .attr("cx", function(result) {
		return x(result.commit.committer_date)
	    })
	    .attr("cy", function(result) {
		return y(sums[result.commit.abbreviated_commit_hash][sum_index])
	    })
	    .on("click", function(result) {
		lsw_summary_graph_click_result(table_id, result)
		d3.event.stopPropagation()
	    })
	    .append("title")
	    .text(function(result) {
		return lsw_commit_texts(result.commits)
	    })
	keys.push({
	    x: keys_x,
	    y: y(sums[last_result.commit.abbreviated_commit_hash][sum_index]),
	    klass: sum_klass[sum_index],
	    text: (sum_index > 0 ? "+" : "") + sum_text[sum_index],
	})
    }

    //
    // The job queue
    //

    // Overlay untested scatter plot
    svg.append("g")
	.selectAll(".dot")
	.data(summary.untested_interesting_commits)
	.enter()
	.append("circle")
	.attr("class", "pending")
	.attr("r", radius)
    	.attr("cx", function(commit) {
	    return x(commit.committer_date)
	})
	.attr("cy", function(commit) {
	    return height-radius
	})
	.append("title")
	.text(function(commit) {
	    return lsw_commit_texts([commit])
	})
    // Overlay the current commit scatter dot.
    if (summary.current.commits.length) {
	svg.append("g")
	    .selectAll(".dot")
	    .data([summary.current])
	    .enter()
	    .append("circle")
	    .attr("class", "current")
	    .attr("r", radius)
    	    .attr("cx", function(d) {
		return x(summary.current.commit.committer_date)
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
    }
    keys.push({
	klass: "current",
	x: x(now) + radius,
	y: height - radius,
	text: "Current",
    })

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
