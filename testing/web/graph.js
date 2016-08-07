function graph(graph) {
    window.addEventListener('load', function() {
	d3.json(graph, function(error, data) {
            if (error) return console.warn(error);

            var parseDate = d3.utcParse("%Y-%m-%d %H:%M");

            // Clean up the fields, make date a date.
            data.forEach(function(d) {
                d.date = parseDate(d.date)
                d.passed = +d.passed
            })

            // In date order.
            data = data.sort(function(l, r) {
                return l.date - r.date
            })

            var margin = {top: 20, right: 20, bottom: 30, left: 50},
		width = 960 - margin.left - margin.right,
		height = 500 - margin.top - margin.bottom;

            var x = d3.scaleTime()
		.range([0, width]);
            var y = d3.scaleLinear()
		.range([height, 0]);

            var xAxis = d3.axisBottom(x)
            var yAxis = d3.axisLeft(y)

            x.domain(d3.extent(data, function(d) { return d.date; }));
            y.domain([d3.min(data, function(d) { return 0.95 * d.passed;}),
                      d3.max(data, function(d) { return 1.05 * d.passed;})]);

            var passedline = d3.line()
		.x(function(d) { return x(d.date); })
		.y(function(d) { return y(d.passed); });

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

            // Add the scatterplot
            svg.selectAll("dot")
		.data(data)
		.enter().append("circle")
		.attr("r", 3.5)
		.attr("cx", function(d) { return x(d.date); })
		.attr("cy", function(d) { return y(d.passed); });

            svg.append("g")
		.attr("class", "y axis")
		.call(yAxis)
		.append("text")
		.attr("transform", "rotate(-90)")
		.attr("y", 6)
		.attr("dy", ".71em")
		.style("text-anchor", "end")
		.text("Passed");

            svg.append("path")
		.datum(data)
		.attr("class", "line")
		.attr("d", passedline)
	})
    });
}
