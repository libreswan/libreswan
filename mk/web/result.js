class Result {
    constructor(obj){
	Object.assign(this, obj)
    }

    output_file(suffix) {
	return this.test_name + "/OUTPUT/" + suffix
    }

    html_issues(directory) {
	if (this.result == "untested") {
	    return ""
	}
	if (!this.test_host_names) {
	    return ""
	}
	return this.test_host_names
	    .map((host, index) => {
		if (this.issues[host] === undefined
		    || this.issues[host].length == 0) {
		    return host+":"+"passed"
		}

		let platform = ""
		if (this.test_guest_platforms[index]) {
		    platform = " ("+this.test_guest_platforms[index]+")"
		}

		return host+":"+this.issues[host]
		    .map((issue) => {
			let href = null
			let value = ""
			if (issue == "passed") {
			    href = host + ".console.txt"
			    value = "passed"
			} else if (issue == "output-different"
				   || issue == "output-whitespace") {
			    href = host + ".console.diff"
			    value = issue
			} else if (issue == "output-unchecked") {
			    href = host + ".console.txt"
			    value = issue
			} else if (issue == "output-truncated") {
			    href = host + ".console.verbose.txt"
			    value = issue
			} else {
			    href = ""
			    value = issue
			}
			return "<a href=\"" + directory + href + "\">" + value + "</a>" + platform
		    }).join(",")
	    }).join("<br/>")

	return html
    }

}
