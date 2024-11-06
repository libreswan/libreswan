function terminal(terminal_txt, terminal_id) {

    let lines = terminal_txt.split("\n")

    let td = d3.select("div#"+terminal_id)
	.append("pre")
	.selectAll("span")
	.data(lines)
	.enter()
	.append("span")

    // prompt# command
    td.filter((line) => line.match(/^[a-z]+#/))
	.selectAll("span")
	.data((line) => line.split("#"))
	.enter()
	.append("span")
	.attr("class", (d, i) => (i == 0 ? "prompt" : "command"))
	.text((d, i) => (i == 0 ? d+"#" : d+"\n"))

    // output
    td.filter((line) => !line.match(/^[a-z]*#/))
	.attr("class", "output")
	.text((line) => line+"\n")

    // comments
    td.filter((line) => line.match(/^#/))
	.attr("class", "comment")
	.text((line) => line+"\n")

}
