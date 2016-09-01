function results(div_id, json_file) {
    window.addEventListener('load', function() {
	d3.json(json_file, function(error, results) {
	    if (error) return console.warn(error)

	    var titles = [
		"Test", "Result", "Expected", "Errors",
		"Boot time", "Script time", "Run Time"
	    ]
	    var errors_index = 3

	    var values = []
	    // need index
	    var i
	    for (i = 0; i < results.length; i++) {
		var result = results[i]
		var line = [
		    result.test_name,
		    result.result,
		    (result.hasOwnProperty("expected_result")
		     ? result.expected_result
		     : ""),
		    // For errors, store the item's index, will fix it
		    // later.
		    i,
		    (result.hasOwnProperty("boot_time")
		     ? result.boot_time
		     : ""),
		    (result.hasOwnProperty("script_time")
		     ? result.script_time
		     : ""),
		    (result.hasOwnProperty("runtime")
		     ? result.runtime
		     : result.hasOwnProperty("total_time")
		     ? result.total_time
		     : "")
		]
		values.push(line)
	    }

            // Init Tidy-Table
            document.getElementById(div_id)
                .TidyTable({
                    enableCheckbox : false,
                    enableMenu     : false,
                }, {
                    columnTitles : titles,
                    columnValues : values,
		    postProcess: {
		        column: function(col) {
			    fixup_results_column(col, errors_index, results)
			}
		    }
		})
	})
    })
}

function fixup_results_column(col, errors_index, results) {
    if (col.cellIndex == 0) {
	// Test Name: href to output directory
	var child = col.childNodes[0]
	test_name = child.data
	var a = document.createElement("a")
	a.setAttribute("href", test_name)
	a.appendChild(document.createTextNode(test_name))
	col.replaceChild(a, child)
    } else if (col.cellIndex == errors_index) {
	var child = col.childNodes[0]
	var result = results[parseInt(child.data)]
	col.removeChild(child)
	if (!result) {
	    col.appendChild(document.createTextNode(""))
	    return
	}
	var br = false
	result.host_names.forEach(function(host) {
	    if (br) {
		col.appendChild(document.createElement('br'))
	    }
	    br = true
	    if (!result.errors.hasOwnProperty(host)
		|| result.errors[host].length == 0) {
		col.appendChild(document.createTextNode(host + ":passed"))
	    } else {
		sep = host + ":"
		result.errors[host].forEach(function(error) {
		    if (sep) {
			col.appendChild(document.createTextNode(sep))
		    }
		    if (error == "passed") {
			col.appendChild(document.createTextNode(error))
		    } else if (error == "output-different"
			       || error == "output-whitespace") {
			var a = document.createElement("a")
			a.setAttribute("href", result.output_directory + "/" + host + ".console.diff")
			a.appendChild(document.createTextNode(error))
			col.appendChild(a)
		    } else if (error == "output-unchecked") {
			var a = document.createElement("a")
			a.setAttribute("href", result.output_directory + "/" + host + ".console.txt")
			a.appendChild(document.createTextNode(error))
			col.appendChild(a)
		    } else if (error == "baseline-missing") {
			// Probably a new test.
			col.appendChild(document.createTextNode("previous-missing"))
		    } else if (error == "baseline-passed") {
			// The current test failed, but the previous
			// test passed.
			col.appendChild(document.createTextNode("previous-passed"))
		    } else if (error == "baseline-failed") {
			// The current test passed, but the previous
			// test failed.
			var a = document.createElement("a")
			a.setAttribute("href", result.baseline_output_directory + "/" + host + ".console.diff")
			a.appendChild(document.createTextNode("previous-failed"))
			col.appendChild(a)
		    } else if (error == "baseline-different"
			       || error == "baseline-whitespace") {
			// The current and previous tests fail, but in
			// different ways.  Ideal would be to show the
			// diff between this and the old test.
			// Showing the old diff might be helpful.
			var a = document.createElement("a")
			a.setAttribute("href", result.baseline_output_directory + "/" + host + ".console.diff")
			a.appendChild(document.createTextNode("previous-different"))
			col.appendChild(a)
		    } else {
			var a = document.createElement("a")
			a.setAttribute("href", result.output_directory)
			a.appendChild(document.createTextNode(error))
			col.appendChild(a)
		    }
		    sep = ","
		})
	    }
	})
    }
}
