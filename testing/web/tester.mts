#!/usr/bin/node

import { execFile } from 'node:child_process'
import path, { dirname, resolve } from 'node:path'

function run(...args) {
    execFile(args[0], args.slice(1), (error, stdout, stderr) => {
	if (error) {
	    throw error
	}
	console.log(stdout)
    })
}

console.log("args:", process.argv0, process.argv)

var tester = path.resolve(process.argv[1])
var bindir = path.dirname(tester)
var web_makedir = path.dirname(tester)
var benchdir = path.resolve(bindir, '..', '..')

console.log(tester, bindir, web_makedir, benchdir)

// run from BENCHDIR so relative make variables work and ./kvm doesn't
// get confused

process.chdir(benchdir)
console.log("cwd:", process.cwd())
