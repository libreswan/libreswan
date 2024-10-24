function lsw_summary_status(id, status) {

    if (!status) {
	return
    }

    let now = new Date()

    let columns = [
	{
	    title: "Current Time",
	    value: function(status) {
		return now
	    },
	    html: function(status) {
		return now.toLocaleString()
	    }
	},
	{
	    title: "Directory",
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
	    title: "Start Time",
	    html: function(status) {
		return status.start_time.toLocaleString()
	    },
	},
	{
	    title: "Last Update",
	    value: function(status) {
		return status.current_time
	    },
	    html: function(status) {
		return status.current_time.toLocaleString()
	    },
	},
	{
	    title: "Run time",
	    value: function(status) {
		return subtime(now, status.start_time)
	    },
	    html: function(status) {
		return subtime(now, status.start_time)
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
