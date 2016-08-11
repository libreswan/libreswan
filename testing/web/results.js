function results(json) {
    window.addEventListener('load', function() {
        $.ajaxSetup({ cache: false });

        // this gets a not well-formed warning
        $.getJSON(json, function(results) {

	    var titles = ["Test", "Result", "Expected", "Errors", "Boot time", "Script time", "Run Time"]
	    var hosts = ["east", "west", "road", "north", "nic"]
	    var errors_index = 3

	    var values = []
	    // need index
	    var i
	    for (i = 0; i < results.table.length; i++) {
		var result = results.table[i]
		var line = []
		line.push(result.testname)
		line.push(result.result)
		line.push(result.hasOwnProperty("expect")
			  ? result.expect
			  : "")
		// Index of this test result
		line.push(i)
		line.push(result.hasOwnProperty("boot_time")
			  ? result.boot_time
			  : "")
		line.push(result.hasOwnProperty("script_time")
			  ? result.script_time
			  : "")
		line.push(result.hasOwnProperty("runtime")
			  ? result.runtime
			  : result.hasOwnProperty("total_time")
			  ? result.total_time
			  : "")
		values.push(line)
	    }

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
			    } else if (col.cellIndex == errors_index) {
				var child = col.childNodes[0]
				var result = results.table[parseInt(child.data)]
				col.removeChild(child)
				if (!result || !result.hasOwnProperty("hosts")) {
				    col.appendChild(document.createTextNode(""))
				    return
				}
				var br = false
				hosts.forEach(function(host) {
				    if (result.hosts.hasOwnProperty(host)) {
					if (br) {
					    col.appendChild(document.createElement('br'))
					}
					br = true
					if (result.hosts[host].length == 0) {
					    col.appendChild(document.createTextNode(host + ":passed"))
					} else {
					    sep = host + ":"
					    result.hosts[host].forEach(function(error) {
						col.appendChild(document.createTextNode(sep))
						if (error == "passed") {
						    col.appendChild(document.createTextNode(error))
						} else if (error == "output-different"
							   || error == "output-whitespace") {
						    var a = document.createElement("a")
						    a.setAttribute("href", result.testname + "/OUTPUT/" + host + ".console.diff")
						    a.appendChild(document.createTextNode(error))
						    col.appendChild(a)
						} else if (error == "output-unchecked") {
						    var a = document.createElement("a")
						    a.setAttribute("href", result.testname + "/OUTPUT/" + host + ".console.txt")
						    a.appendChild(document.createTextNode(error))
						    col.appendChild(a)
						} else {
						    var a = document.createElement("a")
						    a.setAttribute("href", result.testname + "/OUTPUT/")
						    a.appendChild(document.createTextNode(error))
						    col.appendChild(a)
						}
						sep = ","
					    })
					}
				    }
				})
			    }
			}
		    }
		})
	})
    })
}
