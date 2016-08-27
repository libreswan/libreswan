function graph(graph) {
    window.addEventListener('load', function() {
	d3.json(graph, function(error, data) {
            if (error) return console.warn(error);

            var parseDate = d3.utcParse("%Y-%m-%d %H:%M");

	    var names = [
		"passed",
		"failed",
		"unresolved",
		"untested"
	    ]

            // Clean up the fields, make date a date.
            data.forEach(function(d) {
                d.date = parseDate(d.date)
                d.passed = +d.passed
		var results = []
		for (var i = 0; i < names.length; i++) {
		    if (d.hasOwnProperty(names[i])) {
			results.push(+d[names[i]])
		    } else {
			results.push(0)
		    }
		}
		var totals = []
		var total = 0
		for (i = 0; i < results.length; i++) {
		    total += results[i]
		    totals[i] = total
		}
		d.results = results
		d.totals = totals
            })

            // In date order.
            data = data.sort(function(l, r) {
                return l.date - r.date
            })

            var margin = {top: 20, right: 20, bottom: 30, left: 50},
		width = 960 - margin.left - margin.right,
		height = 500 - margin.top - margin.bottom;

            var x = d3.scaleTime()
		.domain(d3.extent(data, function(d) { return d.date; }))
		.range([0, width])
            var y = d3.scaleLinear()
		.domain([d3.min(data, function(d) { return 0.95 * d.totals[0];}),
			 d3.max(data, function(d) { return 1.05 * d.totals[d.totals.length-1];})])
		.range([height, 0])

            var xAxis = d3.axisBottom(x)
            var yAxis = d3.axisLeft(y)

            // should grab div with id=graph
            var svg = d3.select("div").insert("svg")
		.attr("width", width + margin.left + margin.right)
		.attr("height", height + margin.top + margin.bottom)
		.append("g")
		.attr("transform", "translate(" + margin.left + "," + margin.top + ")");

            svg.append("g")
		.attr("class", "x axis")
		.attr("transform", "translate(0," + height + ")")
		.call(xAxis);

            svg.append("g")
		.attr("class", "y axis")
		.call(yAxis)
		.append("text")
		.attr("transform", "rotate(-90)")
		.attr("y", 6)
		.attr("dy", ".71em")
		.style("text-anchor", "end")
		.text("Passed");

	    var iso_date = function(d) {
		d = d.toISOString()
		d = d.match("([^T]*)T([0-9]*:[0-9]*)")
		return d[1] + " " + d[2]
	    }

	    var dots = svg
		.selectAll(".dot")
		.data(data)
		.enter()

	    for (var i = 0; i < names.length; i++) {
		var line = d3.line()
		    .x(function(d) { return x(d.date); })
		    .y(function(d) { return y(d.totals[i]); });
		svg.append("path")
		    .datum(data)
		    .attr("class", "line")
		    .attr("d", line)
		// Overlay scatterplot
		dots.append("circle")
		    .attr("class", names[i])
		    .attr("r", 3.5)
		    .attr("cx", function(d) { return x(d.date); })
		    .attr("cy", function(d) { return y(d.totals[i]); })
		    .on("click", function(d) {
			window.location = d.directory
		    })
		    .append("title")
		    .text(function(d) {
			var text = iso_date(d.date)
			for (j = 0; j <= i; j++) {
				text += "\n" + names[j] + ": " + d.results[j]
			}
			text += "\n" + "total: " + d.totals[i]
			return text
		    })
	    }
	})
    });
}
