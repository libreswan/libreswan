function results(json) {
    window.addEventListener('load', function() {
        $.ajaxSetup({ cache: false });

        // this gets a not well-formed warning
        $.getJSON(json, function(results) {

	    var domains = ["east", "west", "road", "north", "nic"]
	    var headings = ["Test", "Result", "Expected", "Run time"]

	    var titles = headings.slice(0)
	    domains.forEach(function(domain) {
		titles.push(domain)
	    })

	    var values = []
	    results.table.forEach(function(result) {
		var line = [result.testname, result.result, result.expect,
			    result.runtime]
		domains.forEach(function(domain) {
		    if (result.hasOwnProperty("host_results")
			&& result.host_results.hasOwnProperty(domain)) {
			line.push(result.host_results[domain])
		    } else {
			line.push("")
		    }
		})
		values.push(line)
	    })

	    // XXX: track the last test name using a "global"
	    var TEST = ""

            // Init Tidy-Table
            document.getElementById('container')
                .TidyTable({
                    enableCheckbox : false,
                    enableMenu     : false,
                }, {
                    columnTitles : titles,
                    columnValues : values,
		    postProcess: {
		        column: function(col) {
			    if (col.cellIndex == 0) {
				// Test Name: href to output directory
				var child = col.childNodes[0]
				// XXX: see above
				TEST = child.data
				var a = document.createElement("a")
				a.setAttribute("href", TEST + "/OUTPUT")
				a.appendChild(document.createTextNode(TEST))
				col.replaceChild(a, child)
			    } else if (col.cellIndex >= headings.length) { // east ...
				var domain = domains[col.cellIndex - headings.length]
				var child = col.childNodes[0]
				var results = child.data.split(" ")
				col.removeChild(child)
				for (var i = 0; i < results.length; i++) {
				    result = results[i]
				    if (i > 0) {
					col.appendChild(document.createElement('br'))
				    }
				    if (result == "passed") {
					col.appendChild(document.createTextNode(result))
				    } else if (result == "output-different") {
					var a = document.createElement("a")
					// XXX: saved above
					a.setAttribute("href", TEST + "/OUTPUT/" + domain + ".console.diff")
					a.appendChild(document.createTextNode(result))
					col.appendChild(a)
				    } else if (result == "output-unchecked") {
					var a = document.createElement("a")
					// XXX: saved above
					a.setAttribute("href", TEST + "/OUTPUT/" + domain + ".console.txt")
					a.appendChild(document.createTextNode(result))
					col.appendChild(a)
				    } else {
					var a = document.createElement("a")
					// XXX: saved above; just assume it is pluto
					a.setAttribute("href", TEST + "/OUTPUT/" + domain + ".pluto.log")
					a.appendChild(document.createTextNode(result))
					col.appendChild(a)
				    }
				}
			    }
			},
		    },
                });
	})
    })
}
