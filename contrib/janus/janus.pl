#!/usr/bin/perl
#
# janus - Dynamic DNS watcher for FreeS/WAN & forks
# (c) 2004 Tiago Freitas Leal <tfl@netcbo.pt>
#
# This is a fork of ipsec_monitor
# Copyright (C) 2003 by Tim Niemueller <tim@niemueller.de>
# Website: http://www.niemueller.de/software/perl/ipsecmonitor
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# Version: 1.3
# Released: 17.08.2004


#### Modules
use strict;
use Getopt::Long;
use POSIX qw(setsid);
use Fcntl ':flock';
use Socket;

#### Constants, just to make code readable
my $VERSION="1.3";
my $ipsec="/usr/local/sbin/ipsec";
my $janus="/usr/local/bin/janus";

#### Get parameters
my %params=();
GetOptions("help" => \$params{'help'},
	"start" => \$params{'start'},
	"stop" => \$params{'stop'},
	"restart" => \$params{'restart'},
	"script:s" => \$params{'script'},
	"t:i" => \$params{'t'},
	"d" => \$params{'d'},
	"nolog" => \$params{'nolog'},
	"ver" => \$params{'ver'},
	) or usage();

if($params{'help'} ne "") {
	usage();
}

if( ($params{'script'} ne "") && (! -x $params{'script'}) ) {
	failure_exit("The script file does not exist or is not executable.");
}

if($params{'ver'}) {
	print "janus watcher $VERSION\n";
	exit 0;
}

if($params{'t'} eq "") {
	$params{'t'} = 180;
}

#### Signals
$SIG{'TERM'} = \&terminate_daemon;
$SIG{'HUP'} = \&check_status;

#### Globals to make it quick and dirty
my $pid;
my $lockfile = "/var/lock/janus.lock";
my $pidfile = "/var/run/pluto/janus.pid";
my $ctlfile = "/var/run/pluto/janus.ctl";
my $cfgfile = "/etc/ipsec.conf";

#### Main Program, main() like
if($params{'stop'} || $params{'restart'}) { kill_daemon(); } # --stop never returns from this call
startlog("janus_run");
logmsg("info", "Starting janus watcher...");
daemonize(); # only daemon returns from this call
create_lock();
create_pid();
startlog("janus watcher[$$]");
logmsg("info", "Starting Janus - Dynamic DNS watcher (Version $VERSION)");

make_ctl_file();

while (1) {
	sleep $params{'t'};
	check_ctl_file();
}


#### Subs related to reading and writting configuration and control files

sub check_ctl_file {
	my $newadd;
	my $action; # 0 = none; 1 = replace; 2 = replace&pullup; 3 = add; 4 = restart
	open (CTL, "$ctlfile") or failure_exit("unable to open control file");
	my @temp = <CTL>;
	close (CTL);
	open(CTL,">$ctlfile") or failure_exit("unable to open control file");
	flock(CTL, LOCK_EX);

	my $line;
	foreach $line (@temp) {
		chomp ($line);
		my @temp = split(/\,/,$line);
		$action = 0;
		if($temp[1]) {
			if($newadd = gethostbyname($temp[1])) {
				$newadd = join(".", unpack('C4', $newadd));
				if($temp[2] ne $newadd) {
					# Left address has changed, must update connection
					if($temp[0] eq '%local') {
						logmsg("info", "local dynamic: host \"$temp[1]\" changed IP $temp[2] to $newadd");
						$action = 4; # restart only if local dynamic changed
					} else {
						logmsg("info", "\"$temp[0]\": host \"$temp[1]\" changed IP $temp[2] to $newadd");
						$action = 1;
						if($temp[5] eq 'start') {
							$action = 2;
						}
						if(!$temp[2]) {$action = 3;}
					}
					$temp[2] = $newadd;
				}
			}
		}
		if($temp[3]) {
			if($newadd = gethostbyname($temp[3])) {
				$newadd = join(".", unpack('C4', $newadd));
				if($temp[4] ne $newadd) {
					# Right address has changed, must update connection
					logmsg("info", "\"$temp[0]\": host \"$temp[3]\" changed IP $temp[4] to $newadd");
					if(!$action) {
						$action = 1; # replace only if no action for left side
						if($temp[5] eq 'start') {
							$action = 2; # replace&pullup only if no action for left side
						}
					}
					if(!$temp[4]) {$action = 3;}
					$temp[4] = $newadd;
				}
			}
		}
		if($action) {
			if($action eq 1) {
				logmsg("info", "\"$temp[0]\": replacing connection");
				system("$ipsec auto --rereadall");
				system("$ipsec auto --replace $temp[0]");
			} elsif($action eq 2) {
				logmsg("info", "\"$temp[0]\": replacing and pulling up connection");
				system("$ipsec auto --rereadall");
				system("$ipsec auto --replace $temp[0]");
				system("$ipsec auto --up $temp[0]");
			} elsif($action eq 3) {
				logmsg("info", "\"$temp[0]\": adding connection");
				system("$ipsec auto --rereadall");
				system("$ipsec auto --add $temp[0]");
			} elsif($action eq 4) {
				logmsg("info", "Restarting IPSec and janus...");
				system("$ipsec setup --restart");
				system("$janus --restart");
			}
			if($params{'script'}) {
				# We have a script file, wait 60 seconds and then execute it
				sleep 60;
				system($params{'script'});
			}
		}
		print CTL "$temp[0],$temp[1],$temp[2],$temp[3],$temp[4],$temp[5]\n";
	}
	close (CTL);
}

sub make_ctl_file {
	my $section = '';
	my $conn;
	my %default;
	my $auto;
	my $leftconn;
	my $left;
	my $x_leftdynamic;
	my $right;
	my $x_rightdynamic;
	my $addleft;
	my $addright;
	open(CTL,">$ctlfile") or failure_exit("unable to open control file");
	flock(CTL, LOCK_EX);
	open (CONFIG, "$cfgfile") or failure_exit("unable to open config file");
	my @temp = <CONFIG>;
	close (CONFIG);
	my $line;
	foreach $line(@temp) {
		chomp ($line);
		my @temp = split(/[\t= ]+/,$line);
		if($temp[0]) {
			if(($section ne '') && ($temp[0] eq 'conn')) {
				$section = 'conn';
				$conn = $temp[1];
			} else {
				if($temp[0] eq 'config' && $temp[1] eq 'setup') {
					$section = 'conn';
					$conn = '%local';
				}
			}
		} elsif(!$temp[1]) {
			if($section ne 'end') {
				if($conn eq '%default') {
					$default{'left'} = $left;
					$default{'x_leftdynamic'} = $x_leftdynamic;
					$default{'right'} = $right;
					$default{'x_rightdynamic'} = $x_rightdynamic;
					$default{'auto'} = $auto;
					$left = '';
					$x_leftdynamic = '';
					$right = '';
					$x_rightdynamic = '';
					$auto ='';
				} else {
					if(!$left){ $left = $default{'left'}; }
					if(!$x_leftdynamic){ $x_leftdynamic = $default{'x_leftdynamic'}; }
					if(!$right){ $right = $default{'right'}; }
					if(!$x_rightdynamic){ $x_rightdynamic = $default{'x_rightdynamic'}; }
					if(!$auto){ $auto = $default{'auto'}; }
				}
				if($x_leftdynamic eq 'yes') {
					if($conn eq '%local') {
						$leftconn = "local dynamic";
					} else {
						$leftconn = $conn;
					}
					if(!&validip($left) && $left && $left ne '%any') {
						if($addleft = gethostbyname($left)) {
							$addleft = join(".", unpack('C4', $addleft));
							logmsg("info", "\"$leftconn\": watching host \"$left\" on $addleft");
						} else {
							logmsg("info", "\"$leftconn\": name lookup failed for host \"$left\"");
						}
					} else {
						logmsg("info", "\"$leftconn\": ignoring host \"$left\"");
						$left = '';
					}
				} else {
						$left = '';
				}
				if($x_rightdynamic eq 'yes') {
					if(!&validip($right) && $right && $right ne '%any') {
						if($addright = gethostbyname($right)) {
							$addright = join(".", unpack('C4', $addright));
							logmsg("info", "\"$conn\": watching host \"$right\" on $addright");
						} else {
							logmsg("info", "\"$conn\": name lookup failed for host \"$right\"");
						}
					} else {
						logmsg("info", "\"$conn\": ignoring host \"$right\"");
						$right = '';
					}
				} else {
						$right = '';
				}
				if($left ne '' || $right ne '') {
					print CTL "$conn,$left,$addleft,$right,$addright,$auto\n";
				}
				$auto = '';
				$left = '';
				$x_leftdynamic = '';
				$addleft ='';
				$right = '';
				$x_rightdynamic = '';
				$addright = '';
				$section = 'end';
			}
		} else {
			if($conn eq '%local') {
				if($temp[1] eq 'x_localdynamic') {
					$left = $temp[2];
					$x_leftdynamic = 'yes';
				}
			} else {
				if($temp[1] eq 'left') {
					$left = $temp[2];
				} elsif($temp[1] eq 'right') {
					$right = $temp[2];
				} elsif($temp[1] eq 'x_leftdynamic') {
					$x_leftdynamic = $temp[2];
				} elsif($temp[1] eq 'x_rightdynamic') {
					$x_rightdynamic = $temp[2];
				} elsif($temp[1] eq 'auto') {
					$auto = $temp[2];
				}
			}
		}
	}
	flock(CTL, LOCK_UN);
	close (CTL);
}

sub validip {
	my $ip = $_[0];
	if(!($ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)) {
		return 0; }
	else {
		my @octets = ($1, $2, $3, $4);
		foreach $_ (@octets) {
			if(/^0./) {
				return 0; }
			if($_ < 0 || $_ > 255) {
				return 0;
			}
		}
		return 1;
	}
}

#### Subs related to basic program stuff (daemon, fifo, lock etc.)

# Could be modified to syslog for example
sub startlog {
	unless ($params{'nolog'}) {
		use Sys::Syslog qw(:DEFAULT setlogsock);
		setlogsock('unix');
		openlog($_[0], "", "authpriv");
	}
}

sub logmsg {
	my $priority = shift;
	my $msg = shift;

	if($params{'d'}) {
		my $now=localtime();
		print "$now ($priority): $msg, @_\n";
	} else {
		unless ($params{'nolog'}) {
			syslog($priority, $msg, @_);
		}
	}
}

# logs the errors and exits the program
sub failure_exit {
	logmsg("info",$_[0]);
	die $_[0];
}


# Disconnects from console
sub daemonize {
	if(! $params{'d'}) {
		chdir '/' or failure_exit("Can't chdir to /: $!");
		open STDIN, '/dev/null' or failure_exit("daemonize: Can't read /dev/null: $!");
		open STDOUT, '>/dev/null' or failure_exit("daemonize: Can't write to /dev/null: $!");
		defined($pid = fork) or failure_exit("Can't fork: $!");
		exit 0 if $pid;
		setsid() or failure_exit("Can't start a new session: $!");
	}
}

# creates the lockfile
sub create_lock {
	open(LOCK, ">$lockfile");
	my $ok = flock(LOCK, LOCK_EX | LOCK_NB);
	print LOCK $$;
	failure_exit("LOCK janus is already running") if(! $ok);
}

# removes the lockfile
sub remove_lock {
	flock(LOCK, LOCK_UN);
	close(LOCK);
	unlink $lockfile;
}

# creates the pidfile
sub create_pid {
	open(PID, ">$pidfile");
	my $ok = flock(PID, LOCK_EX | LOCK_NB);
	print PID "$$\n";
	failure_exit("PID janus is already running") if(! $ok);
	flock(PID, LOCK_UN);
	flock(PID, LOCK_EX | LOCK_NB);
}

# removes the pidfile
sub remove_pid {
	flock(PID, LOCK_UN);
	close(PID);
	unlink $pidfile;
}

# kills the daemon
sub kill_daemon {
	open(FILE, "$pidfile");
	$pid = <FILE>; chop $pid;
	close (FILE);
	if($pid != 0) {
		system ("/bin/kill $pid");
		if($params{'stop'}) { exit; }
	}
	if($params{'stop'}) { failure_exit("janus isn't running"); }
}

# Terminates daemon closing ISDN connection,
# used as signal handler
sub terminate_daemon {
	alarm 0;	# Stop timer
	remove_lock();
	remove_pid();
	unlink $ctlfile;
	logmsg("info", "Closing down");
	unless ($params{'nolog'}) {
		closelog();
	}
	exit;
}

# prints some basic usage message
sub usage {
	print "janus v.$VERSION (c) 2004 by Tiago Freitas Leal\n",
	"janus is a fork of ipsec_monitor v.0.1 (c) 2003 by Tim Niemueller\n",
	"Watches dynamic DNS hosts and replaces the connection when the IP\n",
	"address changes.\n",
	"Usage:\n",
	"janus [--script=SCRIPT -t t -d -nolog]\n",
	"     Starts janus.\n",
	"janus --restart [--script=SCRIPT -t t -d -nolog]\n",
	"     Kills the present janus task and starts a new one.\n",
	"janus --stop\n",
	"     Stops janus.\n",
	"Options:\n",
	"     --script=SCRIPT: Path to an additional script that is executed\n",
	"                      1 minute after the connection has been replaced.\n",
	"                      For example routing stuff that needs to be done.\n",
	"                      Script must be executable!\n",
	"     -t t: Checks every t seconds if connection parameters have changed.\n",
	"           Default is 180 seconds\n",
	"     -d: Debug mode. Do not fork to background, log output to STDOUT.\n",
	"     --nolog: Don't log.\n\n";
	"janus --ver\n",
	"     Outputs version information.\n",
	exit 0;
}


### END.
