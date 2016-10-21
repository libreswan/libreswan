function lsw_graph_summary(graph_id, summary) {

    var margin = {
	top: 10,
	right: 60,
	bottom: 30,
	left: 50
    }
    var width = 960 - margin.left - margin.right
    var height = 500 - margin.top - margin.bottom
    var radius = 3.5

    var now = new Date()

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
	    d3.min(summary.results, function(d) {
		return 0.8 * d.totals[1]
	    }),
	    d3.max(summary.results, function(d) {
		return 1.02 * d.totals[d.totals.length - 1]
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

    svg.append("g")
	.attr("class", "x axis")
	.attr("transform", "translate(0," + height + ")")
	.call(xAxis)

    svg.append("g")
	.attr("class", "y axis")
	.call(yAxis)
	.append("text")
	.attr("transform", "rotate(-90)")
	.attr("y", 6)
	.attr("dy", ".71em")
	.style("text-anchor", "end")
	.text("Results")

    for (var i = 0; i < lsw_result_names.length; i++) {
	var line = d3.line()
	    .x(function(d) {
		return x(d.commit.committer_date)
	    })
	    .y(function(d) {
		return y(d.totals[i+1])
	    });
	svg.append("path")
	    .datum(summary.first_parent_results)
	    .attr("class", "line")
	    .attr("d", line)
    }

    // Overlay tested scatter plot
    var dots = svg
	.append("g")
	.selectAll(".dot")
	.data(summary.results)
	.enter()
    for (var i = 0; i < lsw_result_names.length; i++) {
	dots.append("circle")
	    .attr("class", lsw_result_names[i])
	    .attr("r", radius)
	    .attr("cx", function(d) {
		return x(d.commit.committer_date)
	    })
	    .attr("cy", function(d) {
		return y(d.totals[i+1])
	    })
	    .on("click", function(d) {
		window.location = d.directory
	    })
	    .append("title")
	    .text(function(d) {
		var text = lsw_commit_text(d.commit)
		var sep = "\n"
		for (j = 0; j <= i; j++) {
		    text += sep + lsw_result_names[j] + ": " + d.results[j]
		    sep = " + "
		}
		return text
	    })
    }

    // Overlay untested scatter plot
    svg.append("g")
	.selectAll(".dot")
	.data(summary.untested_interesting_commits)
	.enter()
	.append("circle")
	.attr("class", "pending")
	.attr("r", radius)
    	.attr("cx", function(d) {
	    return x(d.committer_date)
	})
	.attr("cy", function(d) {
	    return height-radius
	})
	.append("title")
	.text(function(d) {
	    return lsw_commit_text(d)
	})

    // Overlay the current commit scatter dot.
    if (summary.current_commit) {
	svg.append("g")
	    .selectAll(".dot")
	    .data([summary.status])
	    .enter()
	    .append("circle")
	    .attr("class", "current")
	    .attr("r", radius)
    	    .attr("cx", function(d) {
		return x(summary.current_commit.committer_date)
	    })
	    .attr("cy", function(d) {
		return height-radius
	    })
	    .append("title")
	    .text(function(d) {
		return (d.details
			+ "\nStarted: " + lsw_date2iso(new Date(d.start))
			+ "\nLast Update: " + lsw_date2iso(new Date(d.date)))
	    })
    }

    var keys = []
    var last_result = summary.first_parent_results[summary.first_parent_results.length - 1]
    var keys_x = x(last_result.commit.committer_date) + radius
    for (var i = 0; i < lsw_result_names.length; i++) {
	var name = lsw_result_names[i]
	keys.push({
	    name: name,
	    x: keys_x,
	    y: y(last_result.totals[i+1]),
	    text: (i > 0 ? "+" : "") + name.charAt(0).toUpperCase() + name.slice(1),
	})
    }
    keys.push({
	name: "current",
	x: x(now) + radius,
	y: height - radius,
	text: "Current",
    })

    var enter_keys = svg
	.selectAll(".key")
	.data(keys)
	.enter()
	.append("text")
	.attr("class", function(d) {
	    return d.name
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


function lsw_commit_text(commit) {
    return (commit.subject +
	    "\n" + lsw_date2iso(commit.committer_date) + " " + commit.abbreviated_commit_hash)
}
