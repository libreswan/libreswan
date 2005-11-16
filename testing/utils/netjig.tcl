# $Id: netjig.tcl,v 1.53 2005/03/20 23:20:10 mcr Exp $

global theprompt
set theprompt {([a-zA-Z0-9]*):.*# }

global managednets
set managednets {north south northpublic southpublic east west public admin}


proc netjigdebug {msg} {
    global env
    if {[info exists env(NETJIGVERBOSE)]} {
        puts stderr $msg
    }
}

proc netjigcmddebug {msg} {
    global env
    if {[info exists env(NETJIGTESTDEBUG)]} {
	if {$env(NETJIGTESTDEBUG) == "netjig"} {
	    puts -nonewline stderr $msg
	}
    }
}

proc sendnjcmd {netjig cmd} {
    global expect_out(buffer)

    # expect -i $netjig "OK netjig>"
    expect {
    	-i $netjig
	eof	{ puts stderr "EOF in sendnjcmd" }
	timeout	{ puts stderr "timeout in sendnjcmd" }
	"OK netjig>"
    }
    set ncmd [join $cmd]
    netjigcmddebug "Sending $ncmd\n"
    send -i $netjig "$ncmd\n"
    
#    exp_internal 1
    expect {
	-i $netjig
	-re {OK ([0-9]*) LINES} {
	    netjigcmddebug "There are $expect_out(1,string) lines of output\n"
	    return $expect_out(1,string)
	}
	-re {FAIL ([0-9]*) LINES} {
	    set lines $expect_out(1,string)
	    puts "Command failed with output $lines!"
	    exp_internal 1
	    expect -i $netjig -re "netjig>"
	    exit
	}
	timeout {
	    puts "Timeout while talking to netjig for $cmd"
	    puts stderr "Timeout while talking to netjig for $cmd"
	    exit
	}	    
	eof {
	    puts "EOF while talking to netjig for $cmd"
	    puts stderr "EOF while talking to netjig for $cmd"
	    exit
	}	    
    }

    netjigcmddebug "There are $expect_out(1,string) lines of output\n"
    return $expect_out(1,string)
}

proc newswitch {netjig args} {
    global env
    global expect_out(buffer)
    set lines [sendnjcmd $netjig "NEWSWITCH $args"]

#    exp_internal 1
    while {$lines > 0} {
	expect {
		-i $netjig
		eof	{ puts stderr "EOF in newswitch" }
		timeout	{ puts stderr "timeout in newswitch" }
		-re {([^\r\n]*)=([^\r\n]*)}
	}
	set var   $expect_out(1,string)
	set value $expect_out(2,string)
	netjigcmddebug "Setting $var to $value|\n"
	set env($var) $value
	set lines [expr $lines - 1]
    }
}

proc njcmd {netjig cmdline} {
    global env
    global expect_out(buffer)
    set lines [sendnjcmd $netjig "$cmdline"]

    while {$lines > 0} {
	expect {
		-i $netjig
		timeout	{ puts stderr "timeout in njcmd" }
		eof	{ puts stderr "EOF in njcmd" }
		-re {([^\r\n]*)\n}
	}
	set lines [expr $lines - 1]
    }
}    

proc playnjscript {netjig scriptname} {
    set initscript [open $scriptname r]

    while {[gets $initscript line] >= 0} {
	# skip empty lines.
	if {[string length [string trimright $line]] == 0} {
	    continue;
	}	
	njcmd $netjig $line
    }
}

proc netjigsetup {netjig} {
    global env

    # set the packet replay rate, if necessary.
    if {[info exists env(PACKETRATE)]} {
	netjigdebug "setting PACKETRATE: $env(PACKETRATE)"
	njcmd $netjig "setrate $env(PACKETRATE)"
    }
}

proc expectprompt {umlid msg} {
    global theprompt

    trace variable expect_out(buffer) w log_by_tracing
    expect {
	-i $umlid
	-re $theprompt {}
	-re {^\<.\>.*\n}   { exp_continue }
	-re {([^\r\n]*)\n} { exp_continue }
	eof {
	    puts "Cannot find prompt $msg (eof)"
	    puts stderr "Can not find prompt $msg (eof)"
	    shutdownumls
	    exit;
	}
	timeout { 
	    puts "Cannot find prompt $msg (timeout)"
	    puts stderr "Can not find prompt $msg (timeout)"
	    # this ought to be pointless:
	    send -i $umlid "\n echo prompt missing \n"
	    exit
	}
    }
}

proc playscript {umlid scriptname} {
    global theprompt

    trace variable expect_out(buffer) w log_by_tracing

#    exp_internal 1
    set initscript [open $scriptname r]
    while {[gets $initscript line] >= 0} {
	# skip empty lines.
	if {[string length [string trimright $line]] == 0} {
	    continue;
	}	
	if {[string match [string index [string trimleft $line] 0] \#] == 0} {
	    expectprompt $umlid "in playscript $scriptname"

	    # eat any additional previous output
	    expect -i $umlid -gl "*"

	    send -i $umlid -- "$line\r"
	}
    }
    close $initscript
}

proc record {netjig network recordfile} {
    sendnjcmd $netjig "RECORDFILE --switchname=$network --recordfile=$recordfile\n"
}

proc setupplay {netjig network playfile} {
    sendnjcmd $netjig "PLAYFILE --switchname=$network --playfile=$playfile\n"
}

proc waitplay {netjig} {
    set timeout 900
    sendnjcmd $netjig "WAITPLAY\n"
}

proc log_by_tracing {array element op} {
    uplevel {
	global consoleout
	set id $expect_out(spawn_id)

#	puts stderr "\n***** Tracing out ID: $id *******\n"
	if {[ info exists consoleout($id) ]} {
	    puts -nonewline $consoleout($id) $expect_out(buffer)
	}
    }
}

proc shutdown {umlname} {
    system "uml_mconsole $umlname halt"
}

proc shutdownumls {} {
    global umlid
    global managed_hosts

    foreach host $managed_hosts {
	shutdown $host
    }

    foreach host $umlid(extra_hosts) {
	shutdown $host
    }
}


proc startuml {umlname} {
    global umlid
    global consoleout

    if {[info exists umlid($umlname,consolefile)]} {
	set console [open $umlid($umlname,consolefile) w]
	puts $console "Starting UML $umlid($umlname,program)"
    } else {
	set console [open "OUTPUT/$umlname-console-default.txt" w]
    }

    netjigdebug "Starting UML $umlid($umlname,program) for $umlname"

    set umlid($umlname,pid) [spawn $umlid($umlname,program) single]
    set umlid($umlname,spawnid) $spawn_id

    if {[info exists umlid($umlname,consolefile)]} {
	puts $console "spawn $umlid($umlname,program) single"
	netjigdebug "Capturing console output to $umlid($umlname,consolefile)"
    } 
    set consoleout($umlid($umlname,spawnid)) $console
}

proc loginuml {umlname} {
    global umlid
    global theprompt
    
    trace variable expect_out(buffer) w log_by_tracing
    expect {
    	-i $umlid($umlname,spawnid)
	timeout	{ puts stderr "timeout in logginuml" }
	eof	{ 
	          puts stderr "EOF in loginuml" 
    	          shutdownumls
	}
	-exact "normal startup):"
    }
    netjigdebug "\nLogging in to $umlname"
    send -i $umlid($umlname,spawnid) -- "root\r"
}

proc inituml {umlname} {
    global umlid
    global env
    global theprompt
    
    expectprompt $umlid($umlname,spawnid) "before loading module ($umlname)"

    send -i $umlid($umlname,spawnid) -- "echo Starting loading module\r"

    expectprompt $umlid($umlname,spawnid) "for bash exec ($umlname)"

    send -i $umlid($umlname,spawnid) -- "exec bash --noediting\r"

    expectprompt $umlid($umlname,spawnid) "for ulimit ($umlname)"

    send -i $umlid($umlname,spawnid) -- "ulimit -c unlimited\r"

    if {[info exists env(KLIPS_MODULE)]} {
	puts stderr "Loading module into $umlname"

	trace variable expect_out(buffer) w log_by_tracing
	set expect_out(spawn_id) $umlid($umlname,spawnid)
	set expect_out(buffer) ""

	expectprompt $umlid($umlname,spawnid) "before recording memory level ($umlname)"

	send -i $umlid($umlname,spawnid) -- "cat /proc/meminfo >/tmp/proc_meminfo-no-ipsec-mod-01\r" 
	expectprompt $umlid($umlname,spawnid) "for insmod ($umlname)"

	send -i $umlid($umlname,spawnid) -- "insmod /ipsec.o\r"
    } 

    expectprompt $umlid($umlname,spawnid) "for post-insmod ($umlname)"

    send -i $umlid($umlname,spawnid) -- "echo Finished loading module\r"

    expectprompt $umlid($umlname,spawnid) "for klogd ($umlname)"

    send -i $umlid($umlname,spawnid) -- "klogd -c 4 -x -f /tmp/klog.log\r"

    if {[info exists umlid($umlname,initscript)]} {
	playscript $umlid($umlname,spawnid) $umlid($umlname,initscript)
	netjigdebug "$umlname Initialization done"
    }
}

proc runXuml {umlname pass} {
    global umlid
    global env
    global theprompt

    # upcase host name
    set uphost [string toupper $umlname]

    set scriptname run${pass}script
    
    set varname $uphost
    append varname _RUN${pass}_SCRIPT
    set_from_env $umlname $scriptname $varname

    if {[info exists umlid($umlname,$scriptname)]} {
	if {[info exists env(UML_GETTY)]} {
	    send -i $umlid($umlname,spawnid) -- "echo You have 3600 seconds. >/dev/ttys/1\r"
	    send -i $umlid($umlname,spawnid) -- "echo I would run $umlid($umlname,$scriptname) now >/dev/ttys/1\r"
	    send -i $umlid($umlname,spawnid) -- "rm /etc/nologin\r"
	    send -i $umlid($umlname,spawnid) -- "/sbin/getty ttys/1 38400\r"
	    set timeout 3600
	    expectprompt $umlid($umlname,spawnid) "UML_getty for $umlname"
	} 

	if {[file exists $umlid($umlname,$scriptname)]} {
	    playscript $umlid($umlname,spawnid) $umlid($umlname,$scriptname)
	    netjigdebug "$umlname run script($pass) $umlid($umlname,$scriptname) done"
	    return 1
	} else {
	    puts stderr "runXuml($umlname,$pass): $umlid($umlname,$scriptname) does not exist."
	    return 0
	}
    } else {
	netjigdebug "$umlname no run script for pass $pass"
	return 0
    }
}

proc runuml {umlname} {
    global umlid
    global env
    global theprompt

    runXuml $umlname ""
}

proc run2uml {umlname} {
    global umlid
    global env
    global theprompt

    runXuml $umlname 2
}

proc initdns {umlname} {
    global umlid
    global env
    global theprompt

    expectprompt $umlid($umlname,spawnid) "for bash exec ($umlname)"

    send -i $umlid($umlname,spawnid) -- "exec bash --noediting\r"

    expectprompt $umlid($umlname,spawnid) "before sucking in profile ($umlname)"

    send -i $umlid($umlname,spawnid) -- "source \$HOME/.profile\r"

    expectprompt $umlid($umlname,spawnid) "before starting bind ($umlname)"

    send -i $umlid($umlname,spawnid) -- "named\r"

    expectprompt $umlid($umlname,spawnid) "after starting bind ($umlname)"

    send -i $umlid($umlname,spawnid) -- "inetd\r"

    expectprompt $umlid($umlname,spawnid) "after starting inetd ($umlname)"
}

proc killdns {umlname} {
    global umlid
    
    trace variable expect_out(buffer) w log_by_tracing

    #exp_internal 1
    netjigdebug "Sending halt to $umlname!"

    send   -i $umlid($umlname,spawnid)     "halt -p -f\r"

    netjigdebug "Waiting for final message"
    expect {
	-i $umlid($umlname,spawnid)
	timeout	{ puts stderr "timeout in killdns" }
	eof	{ puts stderr "EOF in killdns" }
	-exact "Power down." 
    }
    expect -i $umlid($umlname,spawnid) -gl "*"
}


proc killuml {umlname} {
    global umlid

    trace variable expect_out(buffer) w log_by_tracing

    if {[info exists umlid($umlname,finalscript)]} {
	playscript $umlid($umlname,spawnid) $umlid($umlname,finalscript)
	netjigdebug "Finalscript done"
    } 

    netjigdebug "Sending halt to $umlname!"
    # absorb anything there.

    expectprompt $umlid($umlname,spawnid) "for ipsec setup stop ($umlname)"
    send   -i $umlid($umlname,spawnid)     "ipsec setup stop\r"

    expectprompt $umlid($umlname,spawnid) "for klogd dump ($umlname)"
    send -i $umlid($umlname,spawnid) "kill `cat /var/run/klogd.pid`; cat /tmp/klog.log\r"

    expectprompt $umlid($umlname,spawnid) "for halt ($umlname)"
    send   -i $umlid($umlname,spawnid)     "halt -p -f\r"

    netjigdebug "Waiting for final message"
    expect {
	-i $umlid($umlname,spawnid)
	timeout	{ puts stderr "timeout in killuml" }
	eof	{ puts stderr "EOF in killuml" }
	-exact "Power down." 
    }
    expect -i $umlid($umlname,spawnid) -gl "*"
}

proc process_extra_host {optarg} {
   global umlid

   # format of arg is host=program[, ]host=program.
   set hostlist [split $optarg ", "]
   foreach hosttype $hostlist {
       set h       [split $hosttype =]
       set host    [lindex $h 0]
       set program [lindex $h 1]
       set umlid($host,program) $program
       lappend umlid(extra_hosts) $host
   }
}

proc set_from_env {host param varname} {
    global umlid
    global env
    
    netjigdebug "Looking for $varname..."
    if {[info exists env($varname)]} {
	netjigdebug "found it: $env($varname)"
	set umlid($host,$param) $env($varname)
    }
}


# For each host, the following variables are examined:
# ${HOST}_INIT_SCRIPT     the script to initialize the host with
# ${HOST}_RUN_SCRIPT      the script to run the host with
# ${HOST}_FINAL_SCRIPT    the script to run the host with
# ${HOST}_START   the program to invoke the UML
# REF_${HOST}_CONSOLE_OUTPUT      where to redirect the console output to

proc process_host {host} {
    global umlid
    global env

    # upcase me
    set uphost [string toupper $host]
    set kernver ""
    if {[info exists env(KERNVER)]} {
	set kernver $env(KERNVER)
    }

    set varname $uphost
    append varname _INIT_SCRIPT
    set_from_env $host initscript $varname
	
    set varname $uphost
    append varname _RUN_SCRIPT
    set_from_env $host runscript $varname

    set varname $uphost
    append varname _RUN2_SCRIPT
    set_from_env $host run2script $varname

    set varname $uphost
    append varname _FINAL_SCRIPT
    set_from_env $host finalscript $varname
    
    set varname $uphost
    append varname _START
    set_from_env $host program $varname
    
    set varname REF${kernver}
    append varname _
    append varname $uphost
    append varname _CONSOLE_RAW
    set_from_env $host consolefile $varname
}
    
# {NORTH,SOUTH,EAST,WEST}_PLAY denotes a pcap file to play on that network
# {NORTH,SOUTH,EAST,WEST}_REC  denotes a pcap file to reocrd into from that network
#
# sets umlid(net$net,play) and umlid(net$net,record)
#

proc calc_net {net} {
    global umlid
    global env

    if {[info exists umlid(net$net,play)]} {
	set umlid(someplay) 1
    }
}

proc process_net {net} {
    global umlid
    global env

    # upcase me
    set upnet [string toupper $net]

    set umlid(net$net,arp) 0

    set varname $upnet
    append varname _PLAY
    set_from_env net$net play $varname
	
    set varname $upnet
    append varname _REC
    set_from_env net$net record $varname

    set varname $upnet
    append varname _ARPREPLY
    set_from_env net$net arp $varname

    calc_net $net
}

match_max -d 10000

# $Id: netjig.tcl,v 1.53 2005/03/20 23:20:10 mcr Exp $
#
# $Log: netjig.tcl,v $
# Revision 1.53  2005/03/20 23:20:10  mcr
# 	when looking for an output file for console output,
# 	include the kernel version in the variable that we will
# 	look for.
#
# Revision 1.52  2005/02/11 01:33:46  mcr
# 	added newline to end of file.
#
# Revision 1.51  2005/01/19 00:01:07  ken
# Fix location of klogd.pid - broke due to blind find . patch for moving pluto files to /var/run/pluto
#
# Revision 1.50  2005/01/11 17:54:09  ken
# Move plutos runtime files from /var/run/pluto.* to /var/run/pluto/pluto.*
#
# This was done with find . -type f -print0 | xargs -0 perl -pi -e 's#/var/run/#/var/run/pluto/#g'
#
# Revision 1.49  2004/10/12 03:51:47  mcr
# 	make sure that UMLs run with core dumping enabled.
#
# Revision 1.48  2004/05/05 17:55:20  mcr
# 	fixed problem with getty not licking multiuser boot.
#
# Revision 1.47  2004/05/04 20:05:35  mcr
# 	use ttys/1 rather than tty1.
#
# Revision 1.46  2004/05/04 19:51:46  mcr
# 	make sure to send \r after each command.
#
# Revision 1.45  2004/05/04 19:17:59  mcr
# 	don't try getty unless we have a run command.
#
# Revision 1.44  2004/05/04 18:06:04  mcr
# 	if UML_GETTY is set, then start a getty before running each
# 	runuml command.
#
# Revision 1.43  2004/03/21 04:36:16  mcr
# 	1) local switches now reads testparams.sh file.
# 	2) $arpreply is totally deprecated.
#
# Revision 1.42  2004/02/15 20:37:08  mcr
# 	changed method by which we ask for --arpreply. We can't guess
# 	it, as it doesn't work in all cases like that.
#
# Revision 1.41  2004/02/15 00:12:00  mcr
# 	--arpreply calculation was failing for situation
# 	where the options were specified as arguments.
# 	split process_net -> process_net/calc_net.
#
# Revision 1.40  2004/02/15 00:02:06  mcr
# 	debugging for ARPreply settings.
#
# Revision 1.39  2004/02/05 02:15:51  mcr
# 	added RCS ids.
#
#
