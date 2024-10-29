
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

	let platforms = targets.reduce(
	    function(r, target) {
		if (target.platform) {
		    return r.add(target.platform)
		} else {
		    return r
		}
	    },
	    new Set())

	for (let platform of platforms) {
	    columns.push({
		title: platform,
		html: function(target) {
		    // code below merges platform results
		    if (platform in target) {
			return "<a href=\"" + target.target + "-" + platform + ".log\">" + target[platform] + "</a>"
		    } else {
			return ""
		    }
		},
	    })
	}

	console.log("columns", columns)

	// Merge identical targets

	// Build the table
	let runs = targets.reduce(
	    function(m, target) {
		let mm
		if (m.has(target.target)) {
		    // m[target] already exists, update it
		    mm = m.get(target.target)
		} else {
		    // m[target] doesn't exist, create it
		    mm = new Object()
		    mm["target"] = target.target
		    m.set(target.target, mm)
		}
		// Add the new status
		if (target.platform) {
		    mm[target.platform] = target.status
		} else {
		    mm["all"] = target.status
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
