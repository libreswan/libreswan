#!/usr/bin/expect --

#
# $Id: host-test.tcl,v 1.39 2005/10/20 21:11:45 mcr Exp $
#

source $env(OPENSWANSRCDIR)/testing/utils/GetOpts.tcl
source $env(OPENSWANSRCDIR)/testing/utils/netjig.tcl

proc usage {} {
    global argv0

    puts stderr "Usage: $argv0 "
    puts stderr "\t-i <script>        script to initialize UML"
    puts stderr "\t-s <script>        script to run before data flows"
    puts stderr "\t-I <script>        script to finalize UML"
    puts stderr "\t-n <netjigprog>    path to netjig program"
    puts stderr "\t-a                 if netjig should enable --arpreply"
    puts stderr "\t-D                 start up the UML nic so that there is DNS"
    puts stderr "\t-H host=path,host=path start up additional UMLs as specified"
    puts stderr "\t-p <file>          pcap file to play on private network"
    puts stderr "\t-P <file>          pcap file to play on public network"
    puts stderr "\t-r <file>          record private network to file"
    puts stderr "\t-R <file>          record public network to file"
    puts stderr "\t-u <uml>           User Mode Linux program to start"
    puts stderr "\t-c <file>          file to send console output to"
    puts stderr "\n"
    puts stderr "The following environment variables are also consulted:\n"
    puts stderr "PACKETRATE\tthe rate at which packets will be replayed"
    exit 22
}

set do_playprivate   0
set do_playpublic    0
set do_recordprivate 0
set do_recordpublic  0
set do_consoleoutput 0
set do_dns           0
set timeout 300
log_user 0
if {[info exists env(HOSTTESTDEBUG)]} {
    if {$env(HOSTTESTDEBUG) == "hosttest"} {
	log_user 1
    }
}
set netjig_debug_opt ""
if {[info exists env(NETJIGTESTDEBUG)]} {
    if {$env(NETJIGTESTDEBUG) == "netjig"} {
	set netjig_debug_opt "--debug"
    }
}

netjigdebug "Program invoked with $argv"
set arpreply ""
set umlid(extra_hosts) ""

while { [ set err [ getopt $argv "c:D:H:i:I:n:ap:P:r:R:s:u:U:" opt optarg]] } {
    if { $err < 0 } then {
	puts stderr "$argv0: $opt and $optarg" 
	usage
    } else {
	#puts stderr "Opt $opt arg: $optarg"

	switch -exact $opt {
	    c {
		set umlid(uml,consolefile) $optarg
	    }
	    D {
		process_extra_host "nic=$optarg"
	    }
	    u {
		set umlid(uml,program)    $optarg
	    }
	    U {
		set umlid(uml,host)    $optarg
	    }
	    H {
		# format of arg is host=program[, ]host=program.
		process_extra_host $optarg
	    }
	    i {
		set umlid(uml,initscript) $optarg
	    }
	    I {
		set umlid(uml,finalscript) $optarg
	    }
	    s { 
		set umlid(uml,runscript)   $optarg
            }
	    n {
		set netjig_prog $optarg
	    }
	    a {
		set arpreply "--arpreply"
	    }
	    p {
		set playprivate $optarg
		set do_playprivate 1
	    }
	    P {
		set playpublic $optarg
		set do_playpublic 1
	    }
	    r {
		set recordprivate $optarg
		set do_recordprivate 1
	    }
	    R {
		set recordpublic $optarg
		set do_recordpublic 1
	    }
	}
    }
}

set argv [ lrange $argv $optind end ]

set managed_hosts {}
lappend managed_hosts $umlid(uml,host) 

foreach host $managed_hosts {
    process_host $host
}

if {! [file executable $netjig_prog]} {
    puts "The NETJIG management program is not present. Did you run \"make check\"?"
    exit
}

netjigdebug "Starting up the netjig program: $netjig_prog"

netjigdebug "Will start additional hosts: $umlid(extra_hosts)"

# we start up netjig_prog with a plain pipe, so that
# stderr from it will go to our stderr.
spawn -noecho -open [open "|$netjig_prog --cmdproto $netjig_debug_opt 2>@stderr" w+]
set netjig1 $spawn_id

netjigsetup $netjig1

process_net public
process_net private

newswitch $netjig1 public
newswitch $netjig1 private

# this just gets rid of issues with running without a mcast address
newswitch $netjig1 admin

trace variable expect_out(buffer) w log_by_tracing

# start up auxiliary hosts first
foreach host $umlid(extra_hosts) {
    startuml $host
    loginuml $host
    initdns  $host
}

startuml uml
loginuml uml
inituml  uml

if { $do_recordpublic == 1 } {
    record $netjig1 public $recordpublic
}

if { $do_recordprivate == 1 } {
    record $netjig1 private $recordprivate
}

if { $do_playpublic == 1 } {
    setupplay $netjig1 public $playpublic ""
}

if { $do_playprivate == 1 } {
    setupplay $netjig1 private $playprivate ""
}

runuml uml

# let things settle.
after 500

if { $do_playpublic == 1 || $do_playprivate == 1 } {
    waitplay $netjig1
}

netjigdebug "Finished tests, shutting down"

# see if we should wait
wait_user

after 500

# suck up whatever came out
#expect -i $umlid(uml,spawnid) -gl "*"

#send -i $umlid(uml,spawnid) "\r"

killuml uml
foreach host $umlid(extra_hosts) {
    killdns $host
}

send -i $netjig1 "QUIT\n"
expect {
	-i $netjig1
	timeout { puts "timeout awaiting EOF in host-test.tcl" }
	eof
}

system "sleep 4"

# 
# $Log: host-test.tcl,v $
# Revision 1.39  2005/10/20 21:11:45  mcr
# 	refactored to put wait-user function in netjig.tcl.
#
# Revision 1.38  2004/09/15 21:50:32  mcr
# 	sleep after the test case finishes to give the UML time
# 	to exit cleanly.
#
# Revision 1.37  2004/04/16 19:55:45  mcr
# 	create "admin" network for "eth2" use.
#
# Revision 1.36  2004/04/03 19:44:52  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.35  2003/10/31 02:43:34  mcr
# 	pull up of port-selector tests
#
# Revision 1.34  2003/10/28 03:03:33  dhr
#
# Refine testing scripts:
# - put timeout and eof handlers in each expect script
# - kill more rogue processes: even those with unreadable(!) /proc entries
# - improve reporting of skipped tests
# - make "recordresults" do more, simplifying every caller
# - speed up UML shutdown by using "halt -p -r" (requires many reference log updates)
#
# Revision 1.33  2003/04/02 20:26:53  mcr
# 	quiet down host-test.tcl by using netjigdebug.
#
# Revision 1.32  2003/04/02 02:24:44  mcr
# 	added PACKETRATE setting to host-test.tcl
#
# Revision 1.31  2002/11/04 04:56:09  mcr
# 	when waiting for the user to finish test (NETJIGWAITUSER=waituser)
# 	it is best to wait forever, rather than just until the timeout.
#
# Revision 1.30  2002/11/02 23:03:02  mcr
# 	use new "killdns" function to stop extra hosts.
# 	do not attempt to load module, etc. on extra hosts.
#
# Revision 1.29  2002/11/01 04:17:45  mcr
# 	make sure to initialize umlid(extra_hosts), for the cases
# 	when there are no ADDITIONAL_HOSTS.
#
# Revision 1.28  2002/11/01 02:28:02  mcr
# 	added -H option to *host-test.tcl so give list of additional
# 	hosts that should be started. This is in the form of
# 	host=program,host=program.
# 	Fixed up -D (use DNS) option to instead use the additional
# 	host mechanism.
#
# 	Added "ADDITIONAL_HOSTS" variable to provide a list of
# 	additional hosts that should be started for a given test.
#
# Revision 1.27  2002/10/31 19:01:20  mcr
# 	for consistency, "RUN_SCRIPT" is implemented for "klipstest"
# 	as well as "plutoumltests".
#
# Revision 1.26  2002/10/31 18:51:36  mcr
# 	renamed old "runuml" to "waitplay".
# 	made new function "runuml" which runs a script after
# 	the init, but before the packets start to flow.
# 	There are new variables RUN_{EAST,WEST}_SCRIPT.
#
# Revision 1.25  2002/09/30 18:57:57  mcr
# 	add option "NEED_DNS=true" to start up "nic" UML
# 	for single and 2-host tests. Enabled for "ctltest" only
# 	for now for dns testing.
#
# Revision 1.24  2002/09/18 18:21:40  mcr
# 	if $NETJIGWAITUSER == "waituser" then prompt the user
# 	interactively before terminating test. Useful when debugging.
#
# Revision 1.23  2002/09/02 19:33:45  mcr
# 	the WAITPLAY command did work - it signaled end of
# 	packet stream, but then forgot this fact, and didn't
# 	actually exit.
# 	The netjig.tcl will now log to stderr any problems talking
# 	to uml_netjig, so this problem will be more obvious in
# 	the future.
#
# Revision 1.22  2002/08/29 23:45:23  mcr
# 	fixed up "ctltest" test type
#
# Revision 1.21  2002/08/26 03:15:23  mcr
# 	use "killuml" function only - it now plays the finalscript,
# 	if there is one.
#
# Revision 1.20  2002/08/22 17:42:19  mcr
# 	do not send \r at end of tests, as it is hard
# 	to find one versus two prompts.
#
# Revision 1.19  2002/08/21 21:53:38  mcr
# 	introduced "killuml" function to collect exit behaviour
# 	in one place.
#
# Revision 1.18  2002/08/02 22:31:24  mcr
# 	adjusted to use functions from netjig.tcl
#
# Revision 1.17  2002/07/25 20:09:49  mcr
# 	remove <<<< merge error from end of file.
#
# Revision 1.16  2002/07/23 17:01:32  mcr
# 	added RCS ids
#
#
