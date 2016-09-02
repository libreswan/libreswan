function graph(div_id, data) {

    // In date order.
    data = data.sort(function(l, r) {
        return l.rank - r.rank
    })

    var margin = {top: 20, right: 20, bottom: 30, left: 50}
    var width = 960 - margin.left - margin.right
    var height = 500 - margin.top - margin.bottom

    // XXX: how to get the left bar off the grid with
    // alignment?
    var x = d3.scaleTime()
	.domain([
	    d3.min(data, function(d) { return d.date;}),
	    data[data.length-1].next_date
	])
	.range([1, width])
    var y = d3.scaleLinear()
	.domain([
	    d3.min(data, function(d) { return 0.98 * d.totals[1] }),
	    d3.max(data, function(d) { return 1.02 * d.totals[d.totals.length - 1] })
	])
	.range([height, 0])
	.clamp(true)

    var xAxis = d3.axisBottom(x)
    var yAxis = d3.axisLeft(y)

    var svg = d3.select("#" + div_id)
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
	    .x(function(d) { return x(d.date); })
	    .y(function(d) { return y(d.totals[i+1]); });
	svg.append("path")
	    .datum(data)
	    .attr("class", "line")
	    .attr("d", line)
    }

    // Overlay scatter plot
    var dots = svg
	.selectAll(".dot")
	.data(data)
	.enter()
    for (var i = 0; i < lsw_result_names.length; i++) {
	dots.append("circle")
	    .attr("class", lsw_result_names[i])
	    .attr("r", 3.5)
	    .attr("cx", function(d) { return x(d.date); })
	    .attr("cy", function(d) { return y(d.totals[i+1]); })
	    .on("click", function(d) {
		window.location = d.directory
	    })
	    .append("title")
	    .text(function(d) {
		var text = lsw_date2iso(d.date)
		for (j = 0; j <= i; j++) {
		    text += "\n" + lsw_result_names[j] + ": " + d.results[j]
		}
		text += "\n" + "total: " + d.totals[i+1]
		text += "\n" + "rank: " + d.rank
		return text
	    })
    }
}
