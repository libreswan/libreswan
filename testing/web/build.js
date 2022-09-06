
function build_summary(div_id, json_file) {

    window.addEventListener('load', function() {

	d3.json(json_file, function(error, targets) {

	    if (error) {
		return console.warn(error)
	    }

	    // Describe the table

	    let columns = [
		{
		    title: "Target",
		    html: function(target) {
			return "<a href=\"" + target.target + ".log\">" + target.target + "</a>"
		    },
		},
		{
		    title: "Status",
		    value: function(target) {
			return target.status
		    },
		},
	    ]

	    // Build the table

	    lsw_table({
		id: div_id,
		data: targets,
		columns: columns,
	    })

	})
    })
}
