#!/usr/bin/python
import ujson
import os, commands
import re
from os import listdir
from os.path import isfile, join
import platform
import datetime 
import sys

results = dict() 
testlist = dict()

def read_testlist(resultsdir, node):
	r = resultsdir + "/TESTLIST"
	if not os.path.exists(r):
		return None
	f = open(r, 'r')
	for line in f:
		try:
			testtype, testdir, testexpect = line.split()
		except:
			continue
		if testtype  != "kvmplutotest":
			continue
		testlist[testdir] = testexpect
	f.close

def read_dirs(resultsdir, node): 
	summary  = []

	dirtable = { "columns" : [ "Dir", "Passed", "Failed", "Tests", "Run Time(Hours)"] , "runDir" : node, "suffix" : "",  "rows" : list() }

	newrunpath =  resultsdir
	if node :
		newrunpath =  resultsdir + '/' + node

	dirs = listdir(newrunpath)
	for d in sorted(dirs): 
		# match = re.search(r'(2014-09-16)',d)
		# if not match:
		# 	continue

		td = newrunpath  + '/' + d
		table = { "columns" : [ "Test", "Expected", "Result", "Run time", "east" , "other console"] , "runDir" : '/results/' + os.path.basename(newrunpath) + '/' + d, "suffix" : "/OUTPUT",
				"rows" : list()
				}
		s = print_table_json(td, table, results)
		if not s:
			continue 
		summary.append(s)
		row = []
		row.append(d)
		row.append(s['passed'])
		row.append(s['failed'])
		row.append(s['Total'])
		row.append(s['runtime'])
		dirtable["rows"].append(list(row))

	o = open( resultsdir + '/' + 'graph.json', 'w')
	o.write(ujson.dumps(summary, ensure_ascii=True, double_precision=2)) 
	##print(ujson.dumps(summary, ensure_ascii=True, double_precision=2)) 
	o.close

	t = open(resultsdir + '/' + 'table.json', 'w')
	t.write(ujson.dumps(dirtable, ensure_ascii=True, double_precision=2)) 
	##print(ujson.dumps(summary, ensure_ascii=True, double_precision=2)) 
	t.close 


def  fgrepfor(file, pattern, note):
	if not os.path.exists(file):
		return None

	cmd =  "fgrep  '" + pattern  + "'  " + file 
	match = commands.getoutput(cmd)
	# print("%s"%(cmd))
	if match:
		print("%s"%(cmd))
		return note


def diffstat(d, host):
		diffcmd = 'diff  -N -u -w -b -B'
		initsh =  d + '/' +  host + "init.sh"
		if not os.path.exists(initsh):
			return

		hostr = ''
		goodk =  d + '/' +  host + ".console.txt"
		new  = d + '/OUTPUT/' + host + '.console.txt' 
		if os.path.exists(new):
			if os.path.exists(goodk):
				cmd = diffcmd + ' ' + goodk + ' ' + new + ' | diffstat -f 0'
				ds = commands.getoutput(cmd)
				for line in ds.split("\n")[1:]:
					c = re.sub(r'\d+ file changed,', '', line)
					hostr = host + " " +  c
					#print change
				if not hostr:
					hostr =  host + ' ' + "passed"
			else: 
				hostr =  host + ' missing-baseline'
		else:
			hostr = "missing  OUTPUT/" + host + '.console.txt' 
	
		plutolog = d + '/OUTPUT/' + host + '.pluto.log'
		conslelog = d + '/OUTPUT/' + host + '.console.verbose.txt'
		assertion = fgrepfor(plutolog, 'ASSERTION FAILED', "ASSERT")
		if assertion:
			hostr  = hostr + " " + assertion

		exception = fgrepfor(plutolog, 'EXPECTATION FAILED', "EXPECT")
		if exception:
			hostr  = hostr + " " + exception

		segfault = fgrepfor(conslelog, 'segfault', "SEGFAULT")
		if segfault:
			hostr  = hostr + " " + "SEGFAULT"
			print hostr

		return hostr

	
def diffstat_sum(r,d):
		eastr =  diffstat(d, 'east');
		if eastr:
			r.append(eastr)
		else :
			r.append('east missing-baseline')
		westr =  diffstat(d, 'west');
		rest = ''
		if westr :
			rest =  westr + " "
		roadr =  diffstat(d, 'road');
		if roadr :
			rest = rest +   roadr  + " "
		northr =  diffstat(d, 'north');
		if northr :
			rest = rest + northr

		r.append(rest)

def print_table_json(d, table, result):
	i = 0 
	runtime = 0
	st = dict ()
	try:
		tests = listdir(d)
	except:
		return None
	#print "%s"%d
	for t in tests:
		path = "%s/%s/OUTPUT/RESULT"%(d,t) 
		if not os.path.exists(path):
			continue

		i =  i + 1
		f = open(path, 'r')
		for line in f:
			x = ujson.loads(line)
			if "result" in x and "testname"  in x:
				x["result"] = x["result"].lower()
				r = []
				results[x["testname"]] = x 
				r.append(x["testname"])
				if 'expect' in x:
					r.append(x["expect"])
				elif  x["testname"]  in testlist:
					r.append(testlist[x["testname"]])
				else:
					r.append("expect'")

				r.append(x["result"])
				r.append(x["runtime"])
				runtime = runtime + x["runtime"]
				#print("%s %s %s"%(x["result"], x["testname"], x["runtime"]))
				try:
					st[x["result"]]  =  st[x["result"]]   + 1
				except:
					st[x["result"]]  = 1
				diffstat_sum(r, d + '/' + t)

				table["rows"].append(list(r))
		f.close
	if not st:
		return None
	table["summary"] = dict()
	table["summary"]['failed'] = 0
	table["summary"]['passed'] = 0

	for s in st: 
		table["summary"][s] = st[s]
	table["summary"]["Total"] = i 
	# str(datetime.timedelta(seconds=runtime)
	# table["summary"]["runtime"] = runtime
	hr = runtime // 3600
	min = (runtime % 3600) // 60
	sec = (runtime % 60) 
	table["summary"]["runtime"] = "%02d:%02d:%02d"%(hr, min, sec)
	match = re.search(r'(\d+-\d+-\d+)',d)
	if match:
		table["summary"]["date"] = match.group(1)
	else:
		print("warning missing date in %s. It does not start with date <d+-d+-d+>"%d)

	o = open(d + '/' + 'table.json', 'w')
	o.write(ujson.dumps(table, ensure_ascii=True, double_precision=2)) 
	o.close

	i3html = "../../i3.html"
	if not os.path.exists(d + '/' + "index.html") :
		try :
			os.symlink(i3html, d + '/' + "index.html")
		except :
			pass

	return table["summary"]
