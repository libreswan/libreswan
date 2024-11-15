function results(div_id, json_file) {
    d3.json(json_file, function(error, results) {

	if (error) {
	    return console.warn(error)
	}

	let columns = [
	    {
		title: "Test",
		value: function(result) {
		    return result.test_name
		},
		html: function(result) {
		    return ("<a href=\""
			    + result.test_name
			    + "\">"
			    + result.test_name
			    + "</a>")
		},
	    },
	    {
		title: "Kind",
		value: function(result) {
		    return (result.test_kind !== undefined
			    ? result.test_kind
			    : "")
		},
	    },
	    {
		title: "Status",
		value: function(result) {
		    return (result.test_status !== undefined
			    ? result.test_status
			    : result.expected_result !== undefined
			    ? result.expected_result
			    : "")
		},
	    },
	    {
		title: "Result",
	    },
	    {
		title: "Issues",
		html: function(result) {
		    return result.html_issues(result.test_name + "/")
		},
	    },
	    {
		title: "Boot Time",
	    },
	    {
		title: "Test Time",
	    },
	    {
		title: "Total Time",
	    },
	]

	lsw_table({
	    id: div_id,
	    data: results.map((result) => new TestResult(result)),
	    columns: columns,
	})
    })
}
