function files(files_json, files_id) {

    // convert to a list
    let files = Object.entries(files_json).map((entry, index) => {
	return { "name": entry[0], "url": entry[1] }
    })

    d3.select("div#"+files_id)
	.selectAll("a")
	.data(files)
	.enter()
	.append("div")
	.append("a")
	.attr("href", (file) => file.url)
	.attr("class", "file")
	.text((file) => file.name)

}
