
function build_summary(div_id, json_file) {

    d3.json(json_file, function(error, targets) {

	if (error) {
	    return console.warn(error)
	}

	// Describe the table

	let columns = [
	    {
		title: "Target",
	    },
	    {
		title: "All",
		html: function(target) {
		    if ("all" in target) {
			return "<a href=\"" + target.target + ".log\">" + target.all + "</a>"
		    } else {
			return ""
		    }
		},
	    }
	]

	// Add a column for each OS

	let oss = targets.reduce(
	    function(r, target) {
		if (target.os) {
		    return r.add(target.os)
		} else {
		    return r
		}
	    },
	    new Set())

	for (let os of oss) {
	    columns.push({
		title: os,
		html: function(target) {
		    if (os in target) {
			return "<a href=\"" + target.target + "-" + os + ".log\">" + target[os] + "</a>"
		    } else {
			return ""
		    }
		},
	    })
	}

	console.log("columns", columns)

	// Merge similar targets

	// Build the table
	let runs = targets.reduce(
	    function(m, target) {
		if (m.has(target.ot)) {
		    let mm = m.get(target.ot)
		    mm[target.os] = target.status
		} else {
		    let mm = new Object()
		    mm["target"] = target.ot
		    if (target.os)
			mm[target.os] = target.status
		    else
			mm["all"] = target.status
		    m.set(target.ot, mm)
		}
		return m
	    },
	    new Map()
	)

	console.log("runs", runs)

	lsw_table({
	    id: div_id,
	    data: runs.values(),
	    columns: columns,
	})

    })
}
