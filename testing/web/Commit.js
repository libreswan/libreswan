class Commit {
    constructor(json){
	Object.assign(this, json)
	// now clean up
	this.author_date = new Date(json.author_date)
	this.committer_date = new Date(json.committer_date)
	this.parents = []
	this.children = []
    }

    html(level) {
	let klass = (this.tags ? "tag" :
		     this.parents.length > 1 ? "merge" :
		     this.children.length > 1 ? "branch" :
		     "true")
	let value = (this.tags ? this.tags : klass)

	let html = ""
	html += "<tr class=\"" + klass + "\" title=\"interesting commit: " + value + "\">"
	html += "<td class=\"date\">"
	html += lsw_date2iso(this.author_date)
	html += ":</td>"
	html += "<td class=\"hash\">"
	html += "<a href=\""
	html += "https://github.com/libreswan/libreswan/commit/"
	html += this.hash
	html += "\">"
	html += this.abbrev_hash,
	html += "</a>"
	html += "</td>"
	html += "<td class=\"subject\">"
	for (let l = 0; l < level; l++) {
	    html += "| "
	}
	html += lsw_html_escape(this.subject)
	html += "</td>"
	html += "</tr>"
	return html
    }
}
