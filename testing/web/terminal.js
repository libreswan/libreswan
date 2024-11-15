function terminal(terminal_txt, terminal_id) {

    let lines = terminal_txt.split("\n")

    let td = d3.select("div#"+terminal_id)
	.append("pre")
	.selectAll("span")
	.data(lines)
	.enter()
	.append("span")

    // ENUM
    let OUTPUT = 1
    let COMMENT = 2
    let COMMAND = 3

    let match = (line, type) => {
	if (line.match(/^[a-z]+#/)) {
	    return type == COMMAND
	}
	if (line.match(/^#( |$)/)) {
	    return type == COMMENT
	}
	return type == OUTPUT
    }

    // prompt# command
    td.filter((line) => match(line, COMMAND))
	.selectAll("span")
	.data((line) => line.match(/^([^#]*)#(.*)$/).slice(1,3))
	.enter()
	.append("span")
	.attr("class", (d, i) => (i == 0 ? "prompt" : "command"))
	.text((d, i) => (i == 0 ? d+"#" : d+"\n"))

    // output
    td.filter((line) => match(line, OUTPUT))
	.attr("class", "output")
	.text((line) => line+"\n")

    // comments; not '#2 ...'
    td.filter((line) => match(line, COMMENT))
	.attr("class", "comment")
	.text((line) => line+"\n")

}
