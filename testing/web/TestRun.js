class TestRun {

    constructor(json, commits) {
	Object.assign(this, json)
	// Cleanup the contents
	this.start_time = (json.start_time ? new Date(json.start_time) : null)
	this.current_time = (json.current_time ? new Date(json.current_time) : null)
	// cross link commit and test run
	this.commit = commits[json.hash]
	this.commit.test_run = this
    }

    html_commits() {
	let html = ""
	html += "<table class=\"commits\"><tbody class=\"commits\">"
	html += this._html_first_commits(0, this.commit)
	html += "</tbody></table>"
	return html
    }

    _html_first_commits(level, commit) {
	let html = ""
	while (true) {
	    if (commit.test_run &&
		commit.test_run != this) {
		break;
	    }
	    html += commit.html(level)
	    if (commit.parents.length == 0) {
		break;
	    }
	    for (let l = 1; l < commit.parents.length; l++) {
		html += this._html_first_commits(level+l, commit.parents[l])
	    }
	    let parent = commit.parents[0]
	    if (parent.children.length == 0) {
		break;
	    }
	    if (parent.children[0] != commit) {
		break;
	    }
	    commit = parent
	}
	return html;
    }

}
