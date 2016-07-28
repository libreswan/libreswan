function results(json) {
    window.addEventListener('load', function() {
        $.ajaxSetup({ cache: false });

        // this gets a not well-formed warning
        $.getJSON(json, function(results) {

	    var domains = ["east", "west", "road", "north", "nic"]
	    var titles = ["Test", "Result", "Expected", "Runtime"]
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

            // Init Tidy-Table
            document.getElementById('container')
                .TidyTable({
                    enableCheckbox : false,
                    enableMenu     : false,
                }, {
                    columnTitles : titles,
                    columnValues : values,
		    postProcess: {
		        column: postProcessColumn,
		    },
                });
	});

    })
}

function postProcessColumn(col) {
    if (col.cellIndex == 0) { // Test Name
	var child = col.childNodes[0]
	var text = child.data
        var a = document.createElement("a")
	a.setAttribute("href", text + "/OUTPUT")
	a.appendChild(document.createTextNode(text))
	col.replaceChild(a, child)
    } else if (col.cellIndex >= 4) { // east ...
	var child = col.childNodes[0]
	var results = child.data.split(" ")
        if (results.length > 1) {
            col.removeChild(child)
	    for (var i = 0; i < results.length; i++) {
	        result = results[i]
		if (i > 0) {
		    col.appendChild(document.createElement('br'))
		}
	        col.appendChild(document.createTextNode(result))
            }
        }
    }
}
