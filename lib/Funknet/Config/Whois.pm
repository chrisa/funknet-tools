# $Id$
#
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


package Funknet::Config::Whois;
use strict;

use Net::Whois::RIPE;
use Funknet::Config::Tunnel;
use Funknet::Config::TunnelSet;
use Funknet::Config::BGP;
use Funknet::Debug;

=head1 NAME

Funknet::Config::Whois

=head1 SYNOPSIS

my $whois = Funknet::Config::Whois->new();
my $whois_tun = $whois->tunnels;
my $whois_bgp = $whois->sessions;

=head1 DESCRIPTION

This module contains methods to retrieve configurations from the
objects in the whois database, and create a representation of it using
Funknet::Config objects. The module needs to know what operating
system it is supposed to work with - both in terms of the networking
(local_os) and routing software (local_router). It also needs to know
which Autonomous System the host is in, and an address where the
router interface may be found.

These parameters are picked up from the config file Valid values for
local_os are 'bsd', 'solaris', 'linux' and 'ios'. Valid values for
local_router are 'ios' and 'zebra'.

The parameter local_as expects and 'AS' prefix on the
string. local_host expects an IPv4 address as a dotted-decimal string
(though a hostname may also work, this is asking for trouble).

=head1 METHODS

=head2 sessions

This method retrieves the BGP configuration for the router using the
objects in the whois database. A session is set up for every tunnel,
using the tunnel addresses themselves rather than the endpoint
addresses. 'network' statements are inferred from the route objects in
the local AS by an inverse lookup on the whois database.

The data structure is returned as a hashref. The top level data
structure is Funknet::Config::BGP, which contains the routes
advertised (network statements) for this BGP router. (todo: add other
BGP configuration statements to this object - ebgp multihop etc.)

The BGP object contains a list of Neighbor objects, which represent
the currently configured sessions. 

=head2 tunnels

This method retrieves the tunnel configuration for the router, based
on the tun: attributes of the relevant aut-num object. 

The data structure returned is a reference to an array of
Funknet::Config::Tunnel::$os objects where $os is as indicated by the
local_os flag passed to the constructor.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    debug("Creating a Net::Whois::RIPE object");
    $self->{_net_whois_ripe} = Net::Whois::RIPE->new( 'whois.funknet.org' );
    unless (defined $self->{_net_whois_ripe}) {
	die "couldn't get a Net::Whois::RIPE object";
    }
    $self->{_net_whois_ripe}->source('FUNKNET');
    debug("Done creating a Net::Whois::RIPE object");
    return $self;
}

sub tunnels {
    my ($self) = @_;
    my $w = $self->{_net_whois_ripe};
    my $l = Funknet::Config::ConfigFile->local;
    $w->type('aut-num');
    my $as = $w->query($l->{as});
    
    my @local_tun;
    
    foreach my $tun_name ($as->tun) {
	
	$w->type('tunnel');
	my $tun = $w->query($tun_name);
	
	for my $i ( 0..1 ) {
	    my @as = $tun->as;
	    my @ep = $tun->endpoint;
	    my @ad = $tun->address;
	    
	    # check this tunnel is to our AS and the current endpoint.
	    
	    if ($as[$i] eq $l->{as} && $ep[$i] eq $l->{endpoint}) {

		my $tun_obj = Funknet::Config::Tunnel->new(
		    name => $tun_name,
		    local_address => $ad[$i],
		    remote_address => $ad[1-$i],
		    local_endpoint => $ep[$i],
		    remote_endpoint => $ep[1-$i],
		    type => $tun->type,
		    source => 'whois',
		    proto => '4',
		);
		if (defined $tun_obj) {
		    push @local_tun, $tun_obj;
		}
	    }
	}
    }

    # don't uncomment this; it won't work until we have an 'endpoint' object in 
    # the whois. 

=head2 endpoint object

  endpoint:    SOME-NAME
  type:        ipip
  remote-as:   AS65000
  local-as:    AS65002
  remote-addr: 10.2.0.37
  local-addr:  10.2.0.38
  remote-ep:   131.x.x.x
  local-ep:    213.210.34.174
  encryption:  none
  mnt-by:      ME
  admin-c:     CA1-FUNKNET
  tech-c:      CA1-FUNKNET
  changed:     today

=cut

    if (0) {

	# create tunnels from matching pairs of endpoint objects. 

	foreach my $ep_name ($as->ep) {

	    $w->type('endpoint');
	    my @ep = $w->query($ep_name); # check behaviour of ->query in list context
		
	    # check for match with remote as' endpoint.

	    if ( $ep[0]->remote_as eq $ep[1]->local_as &&
		 $ep[1]->remote_as eq $ep[0]->local_as &&
		 
		 $ep[0]->remote_addr eq $ep[1]->local_addr &&
		 $ep[1]->remote_addr eq $ep[0]->local_addr &&

		 $ep[0]->remote_ep eq $ep[1]->local_ep &&
		 $ep[1]->remote_ep eq $ep[0]->local_ep ) {
		
		# find our end
		
		my $our_ep;
		for my $i ( 0..1 ) {
		    if ($ep[1]->local_ep eq $l->{endpoint}) {
			$our_ep = $i;
		    }
		}
		    
		# cons the tunnel

		push @local_tun, 
		Funknet::Config::Tunnel->new(
		    name => $ep_name,
		    local_address => $ep[$our_ep]->local_addr,
		    remote_address => $ep[$our_ep]->remote_addr,
		    local_endpoint => $ep[$our_ep]->local_ep,
		    remote_endpoint => $ep[$our_ep]->remote_ep,
		    type => $ep[$our_ep]->type,
		    source => 'whois',
		    proto => '4',
		);
	    }
	}
    }

    return Funknet::Config::TunnelSet->new( tunnels => \@local_tun,
					    source => 'whois' );
}

sub sessions {
    my ($self) = @_;
    my $w = $self->{_net_whois_ripe};
    my $l = Funknet::Config::ConfigFile->local;
    
    $w->type('route');
    $w->inverse_lookup('origin');

    my $routes = $w->query_iterator($l->{as});
    my @routes;
    while (my $obj = $routes->next) {
        if (my $route = $obj->route) {
            push @routes, $route;
        }
    }

    $w->type('aut-num');
    $w->{FLAG_i} = '';
    my $as = $w->query($l->{as});

    my $bgp = Funknet::Config::BGP->new( 
	local_as => $l->{as},
	routes  => \@routes,
	source => 'whois');
    
    for my $tun_name ($as->tun) {
	
	$w->type('tunnel');
	my $tun = $w->query($tun_name);

	for my $i ( 0..1 ) {
	    my @as = $tun->as;
	    my @ad = $tun->address;
	    
	    if ($as[$i] eq $l->{as}) {
		
		my $acl_in = Funknet::Config::AccessList->new( source_as   => $as[$i],
							       peer_as     => $as[1-$i],
							       source_addr => $ad[$i],
							       peer_addr   => $ad[1-$i],
							       dir         => 'import',
							       source      => 'whois',
							     );
		
		my $acl_out = Funknet::Config::AccessList->new( source_as   => $as[$i],
								peer_as     => $as[1-$i],
								source_addr => $ad[$i],
								peer_addr   => $ad[1-$i],
								dir         => 'export',
								source      => 'whois',
							      );
		
		$bgp->add_session(
		    description => $tun_name,
		    remote_as => $as[1-$i],
		    local_addr => $ad[$i],
		    remote_addr => $ad[1-$i],
		    acl_in => $acl_in, 
		    acl_out => $acl_out,
		);
	    }
	}
    }
    return $bgp;
}
    

1;
