package Funknet::Config::Host;
use strict;
use Funknet::Config::Tunnel;
use Funknet::Config::TunnelSet;
use Funknet::Config::BGP;
use Funknet::Config::CLI;

=head1 NAME

Funknet::Config::Host.pm

=head1 SYNOPSIS

my $host = Funknet::Config::Host->new();
my $host_tun = $host->tunnels;
my $host_bgp = $host->sessions;

=head1 DESCRIPTION

This module contains methods to retrieve configurations from the
running host or router, and create a representation of it using
Funknet::Config objects. The module needs to know what operating
system it is supposed to work with - both in terms of the networking
(local_os) and routing software (local_router). It also needs to know
which Autonomous System the host is in, and an address where the
router interface may be found.

These parameters are picked up from the config file. Valid values for
local_os are 'bsd', 'solaris', 'linux' and 'ios'. Valid values for
local_router are 'ios' and 'zebra'.

The parameter local_as expects and 'AS' prefix on the
string. local_host expects an IPv4 address as a dotted-decimal string
(though a hostname may also work, this is asking for trouble).

=head1 METHODS

=head2 sessions

This method retrieves the BGP configuration of the router. It uses the
telnet interface available on IOS and Zebra, and the Net::Telnet
module (via Funknet::Config::CLI) to do this.

It needs only the user password to do this, not enable. The passwords
are retrieved from Funknet::Config::Secrets, which is an abstraction
onto some authentication-material store as yet unknown.

The data structure is returned as a hashref. The top level data
structure is Funknet::Config::BGP, which contains the routes
advertised (network statements) for this BGP router. (todo: add other
BGP configuration statements to this object.)

The BGP object contains a list of Neighbor objects, which represent
the currently configured sessions. (todo: retrieve some status from
the router while we are there?)

=head2 tunnels

This method retrieves the current tunnel configuration of the host. It
does this either with 'ifconfig', or via the CLI if local_os is set to
'ios'.

The invocation and initial parsing of ifconfig appears to be portable
across BSD, Linux and Solaris, though this will undoubtedly break. We
separate the main parsing out into Tunnel::BSD, Tunnel::Linux and
Tunnel::Solaris, and return objects appropriately blessed, so the
relevant ->config output method will be called.

The data structure returned is a reference to an array of
Funknet::Config::Tunnel objects. (todo: get some interface stats
here?)

=head1 SPELLING

This entire package mis-spels the word 'Neighbour'. Unfortunately so
do IOS and Zebra, and so this module has to fall into line to avoid
massive confusion.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    return $self;
}

sub tunnels {
    my ($self) = @_;
    my @local_tun;
    my $l = Funknet::Config::ConfigFile->local;

    # special case of cisco needing CLI module
    if ($l->{os} eq 'ios') {

	my $cli = Funknet::Config::CLI->new();
	@local_tun = $cli->get_interfaces;
	
    } else {
	
	# list of interface specs -- actually portable!
	my $c = `/sbin/ifconfig -a`;
	my @if = split /(?=^[a-z])/m,$c;

	for my $if (@if) {

	    warn "considering: $if";

	    chomp $if;
	    my $tun = Funknet::Config::Tunnel->new_from_ifconfig( $if, $l->{os} );
	    if (defined $tun) {
		push @local_tun, $tun;
	    }
	}
    }

    return Funknet::Config::TunnelSet->new( tunnels => \@local_tun,
					    source => 'host' );
}

sub sessions {
    my ($self) = @_;
    
    my $cli = Funknet::Config::CLI->new();
    my $bgp = $cli->get_bgp;
}

1;
