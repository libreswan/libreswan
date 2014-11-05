#!/usr/bin/python
import json
import os, commands
import re
from os import listdir
from os.path import isfile, join
import platform
import datetime 
import sys
import logging

results = dict() 
testlist = dict()

def read_testlist(resultsdir = ''):
	t = "TESTLIST"
	if resultsdir:
		r = resultsdir +  '/' + t
	else :
		r = t

	if not os.path.exists(r):
		return None

	logging.debug ("read tests from %s" % r)

	testlist = dict()
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
	return True

def read_dirs(args, output_dir = ''):

	summary  = []

	dirtable = { "columns" : [ "Dir", "Passed", "Failed", "Tests", "Run Time(Hours)"] , "runDir" : args.node, "suffix" : "",  "rows" : list() }

	newrunpath =  args.resultsdir + '/' + args.node

	dirs = listdir(newrunpath)
	# dirs = [ '2014-09-24-blackswan-v3.10-233-g8602595-hugh-2014aug']
	# print dirs

	for d in sorted(dirs): 
		# match = re.search(r'(2014-09-16)',d)
		# if not match:
		# 	continue

		td = newrunpath  + '/' + d
		if not read_testlist(td):
			logging.info ("can not read a %s/TESTLIST will try other locaations", td)
			if not read_testlist(newrunpath):
				if not read_testlist('./'):
					logging.error ("skip this dir %s. can not read %s/TESTLIST or %s/TESTLIST ./TESTLIST abort", td, td, newrunpath)
					continue

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

	o = open(args.resultsdir + '/' + 'graph.json', 'w')
	o.write(json.dumps(summary, ensure_ascii=True, indent=2))
	##print(json.dumps(summary, ensure_ascii=True, indent=2))
	o.close

	t = open(args.resultsdir + '/' + 'table.json', 'w')
	t.write(json.dumps(dirtable, ensure_ascii=True, indent=2))
	##print(json.dumps(summary, ensure_ascii=True, indent=2))
	t.close 


def  grepfor(file, pattern, note, result, fixed=True):
	if not os.path.exists(file):
		return result
        if fixed:
		fixed = '-F '
	else:
		fixed = ''

	cmd =  "grep " + fixed + "'" + pattern  + "'  " + file 
	match = commands.getoutput(cmd)
	#print("%s"%(cmd))
	if match:
		print("%s %s"%(cmd, result))
		if result:
			result = result + " " + note
		else:
			restult = note
	return result


def diffstat(d, host):
		diffcmd = 'diff  -N -u -w -b -B'
		initsh =  d + '/' +  host + "init.sh"
		if not os.path.exists(initsh):
			return

		hostr = ''
		goodk =  d + '/' +  host + ".console.txt"
		new  = d + '/OUTPUT/' + host + '.console.txt' 
		if os.path.exists(new) and os.path.getsize(new) >  0:
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

		hostr = grepfor(plutolog, 'ASSERTION FAILED', "ASSERT", result = hostr)
		hostr = grepfor(plutolog, 'EXPECTATION FAILED', "EXPECT", result = hostr)
		hostr = grepfor(conslelog, 'segfault', "SEGFAULT", result = hostr)
		hostr = grepfor(conslelog, 'general protection', "GPFAULT", result = hostr) 
		hostr = grepfor(conslelog, "^CORE FOUND$", "CORE", result = hostr, fixed = False)

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

def print_table_json(rpath, table, result):
	i = 0 
	runtime = 0
	st = dict ()
	try:
		tests = listdir(rpath)
	except:
		return None
	rd = os.path.basename(rpath)
	for t in tests:
		r = "%s/%s/OUTPUT/RESULT"%(rpath,t) 
		if not os.path.exists(r):
			continue

		i =  i + 1
		f = open(r, 'r')
		for line in f:
			x = json.loads(line)
			if "result" in x and "testname"  in x:
				x["result"] = x["result"].lower()
				ret = []
				results[x["testname"]] = x 
				ret.append(x["testname"])
				if 'expect' in x:
					ret.append(x["expect"])
				elif  x["testname"]  in testlist:
					ret.append(testlist[x["testname"]])
				else:
					ret.append("expect'")

				ret.append(x["result"])
				ret.append(x["runtime"])
				runtime = runtime + x["runtime"]
				#print("%s %s %s"%(x["result"], x["testname"], x["runtime"]))
				try:
					st[x["result"]]  =  st[x["result"]]   + 1
				except:
					st[x["result"]]  = 1
				diffstat_sum(ret, rpath + '/' + t) 
				table["rows"].append(list(ret))
		f.close
	if not st:
		return None
	table["summary"] = dict()
	table["summary"]['failed'] = 0
	table["summary"]['passed'] = 0
	table["summary"]['dir'] = rd

	for s in st: 
		table["summary"][s] = st[s]
	table["summary"]["Total"] = i 
	# str(datetime.timedelta(seconds=runtime)
	# table["summary"]["runtime"] = runtime
	hr = runtime // 3600
	min = (runtime % 3600) // 60
	sec = (runtime % 60) 
	table["summary"]["runtime"] = "%02d:%02d:%02d"%(hr, min, sec)
	match = re.search(r'(\d+-\d+-\d+)',rd)
	if match:
		table["summary"]["date"] = match.group(1)
	else:
		table["summary"]["date"] = "0000-00-00"
		print("warning missing date in %s. It does not start with date <d+-d+-d+>"%rd)

	o = open(rpath + '/' + 'table.json', 'w')
	o.write(json.dumps(table, ensure_ascii=True, indent=2))
	o.close

	i3html = "../../i3.html"
	if not os.path.exists(rpath + '/' + "index.html") :
		try :
			os.symlink(i3html, rpath + '/' + "index.html")
		except :
			pass

	return table["summary"]
