# Copyright (c) 2003
#	The funknet.org Group.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#	This product includes software developed by The funknet.org
#	Group and its contributors.
# 4. Neither the name of the Group nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE GROUP AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE GROUP OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


package Funknet::Config::Host;
use strict;
use Funknet::Config::Tunnel;
use Funknet::Config::TunnelSet;
use Funknet::Config::BGP;
use Funknet::Config::CLI;
use Funknet::Config::Validate qw/ is_valid_os /;
use Funknet::Debug;

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

=head2 firewall

This method returns a FirewallRuleSet object representing the current
host configuration

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
    my $l = Funknet::ConfigFile::Tools->local;

    unless (ref $l->{os}) {
	$l->{os} = [ $l->{os} ];
    }
    
    for my $t (@{ $l->{os} }) {
	
 	# validate this os, and get its corresponding 
 	# class name (correct capitalisation really).
 	my $tclass;
 	next unless ($tclass = is_valid_os($t));	
	
	no strict;
	push @local_tun, &{"Funknet::Config::Tunnel::".$tclass."::host_tunnels"};
     }

    return Funknet::Config::TunnelSet->new( tunnels => \@local_tun,
					    source => 'host' );
}

sub firewall {
    my ($self, $tun_set, $enc_set) = @_;
    debug("Creating firewall config from Host data");

    my @local_fwall;
    my $fwall_obj;
    my $fwall_set;
    my $l = Funknet::ConfigFile::Tools->local;

    $fwall_obj = Funknet::Config::FirewallRuleSet->new(source => 'host');
    $fwall_set = $fwall_obj->local_firewall_rules;

    return($fwall_set);
}

sub encryption {
    my ($self, $tun_set) = @_;
    my @local_enc;

    for my $tun ($tun_set->tunnels) {
	# try to find some encryption on this tunnel.
	my $enc = Funknet::Config::Encryption->new( tun    => $tun,
						    source => 'host',
						  );
	if (defined $enc) {
	    push @local_enc, $enc;
	}
    }
    my $set = Funknet::Config::EncryptionSet->new( encryptions => \@local_enc,
						   source      => 'host' );
    return $set;
}

sub sessions {
    my ($self) = @_;
    
    my $cli = Funknet::Config::CLI->new();
    my $bgp = $cli->get_bgp;
}

1;
