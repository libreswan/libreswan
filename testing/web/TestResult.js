class TestResult {

    constructor(json) {
	Object.assign(this, json)
    }

    output_file(suffix) {
	return this.test_name + "/OUTPUT/" + suffix
    }

    _html_host_issue(directory, issue, host) {
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
	} else if (issue == "output-unchecked") {
	    href = host + ".console.verbose.txt"
	    value = issue
	} else {
	    href = ""
	    value = issue
	}
	return "<a href=\"" + directory + this.test_name + "/OUTPUT/" + href + "\">" + value + "</a>"
    }

    _html_host_issues(directory, host) {
	return this.issues[host].map((issue) => {
	    return this._html_host_issue(directory, issue, host)
	}).join(",")
    }

    html_issues(directory) {
	if (this.result == "untested") {
	    return ""
	}
	if (!this.test_host_names) {
	    return ""
	}
	let html = this.test_host_names
	    .map((host, index) => {
		let platform = ""
		if (this.test_guest_platforms[index]) {
		    platform = " ("+this.test_guest_platforms[index]+")"
		}
		if (host in this.issues) {
		    return host+":"+this._html_host_issues(directory, host) + platform
		}
		if ("all" in this.issues) {
		    return host+":"+this._html_host_issues(directory, "all") + platform + " (all)"
		}
		return host+":passed"
	    })
	if ("all" in this.issues) {
	    html.push("all:"+this._html_host_issues(directory, "all"))
	}
	return html.join("<br/>")
    }

}
