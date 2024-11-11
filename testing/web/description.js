function description(description_txt, description_id) {

    let lines = description_txt.split("\n")

    let title = lines.shift() // first line; and drop it

    d3.select("div#"+description_id)
	.selectAll("h1")
	.data([title])
	.enter()
	.append("h2")
	.text((title) => title)

    // drop any blank lines between the title and the body
    while (lines.length > 0 && !lines[0]) {
	lines.shift()
    }

    let description = lines.join("\n") // single blob

    d3.select("div#"+description_id)
	.selectAll("pre")
	.data([description])
	.enter()
	.append("pre")
	.text((line) => line)

}
