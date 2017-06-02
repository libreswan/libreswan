function lsw_summary_status(id, status) {

    if (!status) {
	return
    }

    var now = new Date()

    var columns = [
	{
	    title: "Current Time",
	    value: function(status) {
		return now
	    },
	    html: function(status) {
		return lsw_date2iso(now)
	    }
	},
	{
	    title: "Directory",
	    value: function(status) {
		return status.directory
	    },
	    html: function(status) {
		if (status.directory && status.directory.length) {
		    return ("<a href=\"" + status.directory + "\">"
			    + status.directory
			    + "</a>")
		} else {
		    ""
		}
	    }
	},
	{
	    title: "Last Update",
	    value: function(status) {
		return status.date
	    },
	    html: function(status) {
		return status.date ? lsw_date2iso(status.date) : ""
	    },
	},
	{
	    title: "Details",
	},
    ]

    lsw_table({
	id: id,
	data: [status],
	columns: columns,
    })
}
