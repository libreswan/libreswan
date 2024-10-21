class Commits {
    constructor(commits) {

	// turn raw json into proper objects, retain (new-to-old)
	// order
	let i = 0
	this.commits = commits.map((json) => {
	    return new Commit(json, i++)
	})

	// build the hash map
	this.hash_to_commit = []
	for (let commit of this.commits) {
	    this.hash_to_commit[commit.hash] = commit
	}

	// fill in parents
	for (let json of commits) {
	    let commit = this.hash_to_commit[json.hash]
	    for (let parent_hash of json.parents) {
		let parent = this.hash_to_commit[parent_hash]
		if (parent) {
		    commit.parents.push(parent)
		} else {
		    console.log("commit",commit, "has no parent", parent_hash)
		}
	    }
	}

	// fill in children
	for (let commit of this.commits) {
	    for (let parent of commit.parents) {
		parent.children.push(commit)
	    }
	}

	/* save oldest and and newest based on commit date */
	this.oldest = this.commits.reduce((oldest, commit) => {
	    return oldest.commit_date < commit.commit_date ? oldest : commit
	}, this.commits[0])
	this.newest = this.commits.reduce((newest, commit) => {
	    return newest.commit_date > commit.commit_date ? newest : commit
	}, this.commits[0])

	console.log("commits", i, this)
    }
}
