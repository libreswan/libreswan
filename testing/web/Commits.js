class Commits {
    constructor(commits_json) {

	// turn raw json into proper objects, retain (new-to-old)
	// order
	let i = 0
 	this.commits = commits_json.map((json) => {
	    return new Commit(json, i++)
	})

	// build the hash map
	this.hash_to_commit = []
	for (let commit of this.commits) {
	    this.hash_to_commit[commit.hash] = commit
	}

	// fill in parents
	for (let commit_json of commits_json) {
	    let commit = this.hash_to_commit[commit_json.hash]
	    for (let parent_hash of commit_json.parents) {
		let parent = this.hash_to_commit[parent_hash]
		if (parent) {
		    commit.parents.push(parent)
		} else {
		    console.log("commit",commit, "has no parent", parent_hash)
		}
	    }
	}

	// fill in children
	//
	// walk first parent before walking second parent so that
	// first child back link is to first parent
	this._fill_children(this.commits[0])

	/* save oldest and and newest based on commit date */
	this.oldest = this.commits.reduce((oldest, commit) => {
	    return oldest.commit_date < commit.commit_date ? oldest : commit
	}, this.commits[0])
	this.newest = this.commits.reduce((newest, commit) => {
	    return newest.commit_date > commit.commit_date ? newest : commit
	}, this.commits[0])

	console.log("commits", i, this)
    }

    _fill_children(child) {
	// assume child has at least one parent
	let branches = []
	branches.push([child, 0])
	while (branches.length > 0) {
	    let [child, level] = branches.pop()
	    do {
		if (child.parents.length > level+1) {
		    branches.push([child, level+1])
		}
		let parent = child.parents[level]
		if (parent.children.includes(child)) {
		    break
		}
		parent.children.push(child)
		child = parent
		level = 0
	    } while (child.parents.length > 0)
	}
	return
    }

}
