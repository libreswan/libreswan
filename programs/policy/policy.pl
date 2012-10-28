#!/usr/bin/perl -w
use strict;
use warnings;
use Pod::Usage;
use Getopt::Long;
use POSIX qw( EXIT_SUCCESS EXIT_FAILURE );

# ------------------------------------------------------------------------
# This next POD section is used by pod2usage to generate --help output,
# and is used by the makefile to generate a man page.
#
=head1 NAME

ipsec_policy - show ipsec policy information

=head1 SYNOPSIS

    # detect what stack is used
    ipsec policy --detect-stack

    # display policy information
    ipsec policy [ --all | [ --inbound | --outbound | --forward ] ] \
                 [ --stack=name ] [ --read=file ] [ --debug ]

    # provide usage information
    ipsec policy --usage
    ipsec policy --help

=head1 DESCRIPTION

I<policy> displays the incoming, outgoing, and forwarding packet policies of
the system.  It is a wrapper around eixsting klips and netkey data, but
presented in a less terse form.

=head1 OPTIONS

=over 4

=item --detect-stack

Only display the stack that Libreswan is using.  Possible results are.

=over 4

=item klips

KLIPS is the Libreswan ipsec kernel module.  This stack type indicates that
KLIPS is not running in I<mast> mode (see next option), but rather in the 
default mode.  In this mode, KLIPS outgoing packet policy is dicated by
I<eroutes>.  See the B<ipsec_eroute> man page for further details.

=item mast

This is a mode of the Libreswan ipsec kernel module, KLIPS.  In this mode
outgoing packet routing policies are dictated by iptalbles, and Linux kernel
policy routing.  This mode is selected by using C<protostack=mast> setting in
I<ipsec.conf>.

=item netkey

This stack indicates that Libreswan is controlling the Linux kernel built-in
ipsec functionally.

=back


=item --all

Show inbound, outbound, and forward policites.  This is the default.

=item --inbound --in

Show only inbound policy.

=item --outbound --out

Show only outbound policy.

=item --forward --fwd

Show only forward policy.

=item --stack=<name>

Skip autodetection and force read policy from this stack.  See help on
B<--detect-stack> (above) for valid options and their descriptions.

=item --read=<file>

This option overrides what file would be read to gather the policy
information.  It could be used to read policy information from a snapshot
obtained from a running system.

In the case of the klips or mast stack, this file is the output of the
B</proc/net/ipsec/spi/all> file.

=item --help

Output help.

=item --debug

Output debug info.

=back

=head1 FILES

   /proc/net/ipsec/spi/all

=head1 SEE ALSO

B<ipsec>(8), B<ipsec_eroute>(8), B<ipsec_manual>(8)

=head1 HISTORY

Designed for the Libreswan project <http://www.libreswan.org> by Bart
Trojanowski.

=head1 BUGS

Does not support netkey yet.

=cut

# ------------------------------------------------------------------------
# general helper functions

my $debug = 0;
sub dbg
{
        my $txt = "@_";
        chomp $txt;
        warn "# $txt\n" if $debug;
}

sub assert_root
{
        my $txt = join(' ', @_);
        dbg "your uid is $>";
        if ($> ne 0) {
                die "You need to be root"
                    . (length($txt)==0 ? "." : " $txt")
                    . "\n";
        }
}

# ------------------------------------------------------------------------
# detect stack and print sadb
package Stack;
use vars qw($debug);
use subs qw(dbg assert_root);
*dbg = \&::main::dbg;
*assert_root = \&::main::assert_root;

sub detect_ipsec_stack
{
        my $class = shift;

        assert_root "to detect the ipsec stack; try --stack= and --read=.";

        my $os_mode = Stack::Klips->detect_libreswan_stack_mode();
        return $os_mode if (defined $os_mode);

        die "We don't support netkey yet.\n";
}

sub new
{
        my $class = shift;
        my (%args) = @_;

        my $stack_name = $args{name};
        $stack_name = $class->detect_ipsec_stack() if not defined $stack_name;
        dbg "stack name is $stack_name";

        my $subclass = 'Stack::' . ucfirst($stack_name);
        dbg "subclass is $subclass";

        my $instance = eval { $subclass->new(%args) };
        if($@) { die "Unknown stack: $stack_name\nERROR: $@\n" };

        $instance->initialize_spdb();

        return $instance;
}

sub initialize_spdb
{
        my $this = shift;

        $this->{spdb} = {};
        $this->{spnames} = {
                'in'  => [],
                'out' => [],
                'fwd' => [],
        };
}

sub add_spdb_entry
{
        my $this = shift;
        my ($entry) = @_;

        my $name = $entry->{name};
        ${$this->{spdb}}{$name} = $entry;

        my $dir = $entry->{dir};
        if ( $dir ne 'in' and $dir ne 'out' ) {
                die "line $. has neither dir=in nor dir=out set\n";
        }

        push @{${$this->{spnames}}{$dir}}, $name;
}

sub print_spi
{
        my $this = shift;
        my ($prefix,$s) = (@_);

        return unless ($s->{'xform'} eq 'IPIP');
        return unless (defined $s->{'policy'});

        my @p = split("->", $s->{'policy'});

        printf "%-3s  %-10d   %-18s -> %-18s     %s     ref:%d him:%d\n",
                $prefix,
                $s->{'life_packets_c'} || 0,
                $p[0],
                $p[1],
                $s->{'name'},
                $s->{'ref'},
                $s->{'refhim'};
}

sub print_spdb_dir
{
        my $this = shift;
        my ($prefix, @names) = (@_);

        for my $name (sort @names) {
                my $s = ${$this->{spdb}}{$name};
                $this->print_spi($prefix, $s);
        }
}

sub print_spdb
{
        my $this = shift;

        print STDERR "stack: " . $this->name() . "\n";

        dbg "show: " . join (',',@{$this->{show}});
        for my $what (@{$this->{show}}) {
                $this->print_spdb_dir(uc $what, @{${$this->{spnames}}{$what}});
        }
}




# ------------------------------------------------------------------------
# klips specific code
package Stack::Klips;
our @ISA = qw( Stack );
use vars qw($debug);
use subs qw(dbg assert_root);
*dbg = \&::main::dbg;
*assert_root = \&::main::assert_root;

# some well known files
my $klips_proc_version='/proc/net/ipsec/version';
my $klips_proc_spi_all='/proc/net/ipsec/spi/all';

sub have_libreswan
{
        my $class = shift;

        return 0 if system('which ipsec >/dev/null 2>&1');
        return 0 if system('ipsec version >/dev/null 2>&1');
        dbg "detected libreswan binaries";
        return 1;
}

sub have_klips_module
{
        my $class = shift;

        return 0 if not -e $klips_proc_spi_all;
        return 0 if not -e $klips_proc_version;
        return 0 if system("cat $klips_proc_version 2>/dev/null | grep -q '^Libreswan'");
        dbg "detected libreswan module";
        return 1;
}

sub detect_libreswan_stack_mode
{
        my $class = shift;

        return () if not have_libreswan;
        return () if not have_klips_module;

        return () if not open(IN, 'ipsec whack --status |');
        my $ifline = <IN>;
        close(IN);
        dbg "read: $ifline";

        return () if not $ifline =~ m/using kernel interface: (\w+)$/;
        return () if $1 ne 'klips' and $1 ne 'mast';
        dbg "detected libreswan in $1 mode";
        return $1;
}

sub new
{
        my $class = shift;
        my (%args) = @_;
        my %defaults = (
                read => $klips_proc_spi_all
        );
        my $this = { %defaults };
        bless $this, $class;
        # assign args
        while (my ($k,$v) = each(%args)) {
                next if not defined $v;
                dbg "arg $k is $v";
                $this->{$k} = $v 
        }
        return $this;
}

sub name
{
        return "klips"
}

sub read_spdb
{
        my $this = shift;

        my $input = $this->{read};
        dbg "reading from $input";
        assert_root "to read the policy database in $input." if not -r $input;

        open(SPI, "< $input") || die "failed to read $input\n";
        while (<SPI>) {
                m/^(\S+) (\S+): (.*)$/ || die "couldn't parse line $.: $_";
                my ($name, $xform, $rest) = ($1, $2, $3);

                my $tmp = { name  => $name,
                        xform => $xform };

                dbg '-' x 70;
                dbg "$name";
                dbg "$xform";
                dbg "$rest";

                foreach my $word (split /\s+/, $rest) {
                        $word =~ m/^(\S+)=(\S+)$/ || die "couldn't parse part of line $.: $word\n";
                        my ($var, $val) = ($1, $2);

                        dbg "  $var = $val";

                        $tmp->{$var} = $val;

                        if ($var eq 'life(c,s,h)') {
                                # life(c,s,h)=bytes(19240,0,0)addtime(811,0,0)usetime(784,0,0)packets(185,0,0)
                                for my $n (qw{bytes addtime usetime packets}) {
                                        if ($val =~ m/$n\((\d+),(\d+),(\d+)\)/) {
                                                dbg "    life_${n}_c = $1";
                                                dbg "    life_${n}_s = $2";
                                                dbg "    life_${n}_h = $3";

                                                $tmp->{"life_${n}_c"} = $1;
                                                $tmp->{"life_${n}_s"} = $2;
                                                $tmp->{"life_${n}_h"} = $3;
                                        }
                                }
                        }
                }

                $this->add_spdb_entry($tmp);
        }
        close(SPI);
}

# ------------------------------------------------------------------------
# mast specific code
package Stack::Mast;
our @ISA = qw( Stack::Klips );
use vars qw($debug);
use subs qw(dbg assert_root);
*dbg = \&::main::dbg;
*assert_root = \&::main::assert_root;

sub name
{
        return "mast"
}

# everything here is inhered from Klips (for now)

# ------------------------------------------------------------------------
# netkey specific code
package Stack::Netkey;
our @ISA = qw( Stack );
use vars qw($debug);
use subs qw(dbg assert_root);
*dbg = \&::main::dbg;
*assert_root = \&::main::assert_root;

sub new
{
        my $class = shift;
        my (%args) = @_;
        my %defaults = (
                # some defaults can go here
        );
        my $this = { %defaults };
        bless $this, $class;
        # assign args
        while (my ($k,$v) = each(%args)) {
                next if not defined $v;
                dbg "arg $k is $v";
                $this->{$k} = $v 
        }
        return $this;
}

sub name
{
        return "netkey"
}

sub read_spdb
{
        my $this = shift;
        print "Netkey read_spdb\n";
}

# ------------------------------------------------------------------------
# this is the main part of the program
package main;
my $show_all = 0;
my $show_inbound = 0;
my $show_outbound = 0;
my $show_forward = 0;
my $opt_stack;
my $opt_read;

my $rc = GetOptions(
        # detection only mode
        'detect-stack' => sub { print "stack=" . Stack->detect_ipsec_stack() . "\n"; exit 0 },
        # what to show
        'all'       => \$show_all,
        'inbound'   => \$show_inbound,
        'in'        => \$show_inbound,
        'outbound'  => \$show_outbound,
        'out'       => \$show_outbound,
        'forward'   => \$show_forward,
        'fwd'       => \$show_forward,
        # what to read
        'stack=s'   => \$opt_stack,
        'read=s'    => \$opt_read,
        # generic stuff
        'debug'     => \$debug,
        # help
        'usage'     => sub { pod2usage(-exitval => EXIT_SUCCESS, -verbose => 0) },
        'help'      => sub { pod2usage(-exitval => EXIT_SUCCESS, -verbose => 1) },
);
pod2usage('Invalid options specified.') if !$rc;

if ($show_all) {
        # show everything
        $show_inbound = $show_outbound = $show_forward = 1;

} elsif (not ($show_inbound | $show_outbound | $show_forward)) {
        # by default show only outbound policies
        $show_outbound = 1;
}

# collect names of policies to display
my @show = ();
push @show, 'in'  if $show_inbound;
push @show, 'out' if $show_outbound;
push @show, 'fwd' if $show_forward;

# get a new stack object
my $s = Stack->new(
        name => $opt_stack,
        read => $opt_read,
        show => \@show,
);

$s->read_spdb();
$s->print_spdb();

