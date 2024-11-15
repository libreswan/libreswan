function result(result_json, title_id, description_id, result_id) {

    console.log(result_json)

    // URL/RESULTS/TEST/index.html
    let path = window.location.pathname.split("/")
    let test = path[path.length - 2]
    d3.select("div#"+title_id)
	.selectAll("h1")
	.data([test])
	.enter()
	.append("h1")
	.text((test) => test)

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
		return result.html_issues("")
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
