class Status {
    constructor(json) {
	this.details = json.details
	this.directory = json.directory
	this.start_time = new Date(json.start_time)
	this.current_time = new Date(json.current_time)
    }
}
