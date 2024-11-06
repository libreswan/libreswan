function result(result_json, result_id) {

    console.log(result_json)
    let results = [result_json]

    let columns = [
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
		return result.html_issues("OUTPUT")
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
	id: result_id,
	data: results.map((result) => new TestResult(result)),
	columns: columns,
    })

}
