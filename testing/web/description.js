function description(description_txt, title_id, description_id) {

    let lines = description_txt.split("\n")

    // URL/RESULTS/TEST/index.html
    let path = window.location.pathname.split("/")
    let test = path[path.length - 2]
    let title = test + ": " + lines.shift() // first line; and drop it

    d3.select("div#"+title_id)
	.selectAll("h1")
	.data([title])
	.enter()
	.append("h1")
	.text((title) => title)

    // drop any leading blank lines
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
