#!/usr/bin/perl -w
#
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

use Funknet::Whois::Client;
use Funknet::Config::Tunnel;
use Funknet::Config::TunnelSet;
use Funknet::Config::BGP;
use Funknet::Config::Encryption;
use Funknet::Config::EncryptionSet;
use Funknet::Config::FirewallRule;
use Funknet::Config::FirewallRuleSet;
use Funknet::Debug;

use base qw/ Funknet::Config /;

=head1 NAME

Funknet::Config::Whois

=head1 SYNOPSIS

my $whois = Funknet::Config::Whois->new();
my $whois_tun = $whois->tunnels;
my $whois_bgp = $whois->sessions;
my $whois_enc = $whois->encryption;
my $whois_fwall = $whois->firewall;

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
    debug("Creating a Funknet::Whois::Client object");
    my $host = Funknet::ConfigFile::Tools->whois_host || 'whois.funknet.org';
    my $port = Funknet::ConfigFile::Tools->whois_port || 43;
    $self->{_fwc} = Funknet::Whois::Client->new($host, 
						Timeout => 10, 
						Port    => $port);
    unless (defined $self->{_fwc}) {
	die "couldn't get a Funknet::Whois::Client object";
    }
    $self->{_fwc}->source(Funknet::ConfigFile::Tools->whois_source || 'FUNKNET');
    debug("Done creating a Funknet::Whois::Client object");
    return $self;
}

sub my_tunnels {
    my ($self) = @_;
    my $w = $self->{_fwc};
    my $l = Funknet::ConfigFile::Tools->local;
    $w->type('aut-num');
    my $as = $w->query($l->{as});
    
    my @local_tuns;

    foreach my $tun_name ($as->tun)
    {
        $w->type('tunnel');
        my $tun = $w->query($tun_name);
        push (@local_tuns, $tun);
    }
    return(@local_tuns);
}

sub tunnels {
    my ($self) = @_;
    my $w = $self->{_fwc};
    my $l = Funknet::ConfigFile::Tools->local;
    $w->type('aut-num');
    my $as = $w->query($l->{as});
    
    if (defined $as) {
	debug("loaded aut-num for $l->{as}");
    } else {
	$self->warn("aut-num not found for $l->{as}");
	return undef;
    }
    
    my @local_tun;
  TUNNEL: foreach my $tun_name ($as->tun) {
	$w->type('tunnel');
	my $tun = $w->query($tun_name);

	if (defined $tun) {
	    debug("loaded tunnel for $tun_name");
	} else {
	    $self->warn("tunnel object $tun_name missing?");
	    next TUNNEL;
	}
	
	for my $i ( 0..1 ) {
	    my @as = $tun->as;
	    my @ep = $tun->endpoint;
	    my @ad = $tun->address;


	    # check this tunnel is to our AS and one of the current endpoints.
	    
	    my $tun_obj;
	    if ($as[$i] eq $l->{as} && _is_current_endpoint($l, $ep[$i])) {

		$tun_obj = Funknet::Config::Tunnel->new(
							name => $tun_name,
							local_address => $ad[$i],
							remote_address => $ad[1-$i],
							local_endpoint => $ep[$i],
							remote_endpoint => $ep[1-$i],
							type => $tun->type,
							source => 'whois',
							proto => '4',
                                                        order => $i,
						       );

            # handle the case where we have a local_public_endpoint parameter

	    } elsif (defined $l->{public_endpoint} && $as[$i] eq $l->{as} && $ep[$i] eq $l->{public_endpoint}) {

                $tun_obj = Funknet::Config::Tunnel->new(
							name => $tun_name,
							local_address => $ad[$i],
							remote_address => $ad[1-$i],
							local_endpoint => $l->{endpoint},
							remote_endpoint => $ep[1-$i],
							type => $tun->type,
							source => 'whois',
							proto => '4',
                                                        order => $i,
						       );
            }
	    if (defined $tun_obj) {
		push @local_tun, $tun_obj;
	    }
	}
    }

    return Funknet::Config::TunnelSet->new( tunnels => \@local_tun,
					    source  => 'whois' );
}

sub firewall {
    my ($self, $tun_set) = @_;
    debug("Creating Firewall config from Whois data");

    my $w = $self->{_fwc};
    my $l = Funknet::ConfigFile::Tools->local;
    $w->type('aut-num');
    my $as = $w->query($l->{as});
    
    my @local_fwallrule;
    
    foreach my $tun ($tun_set->tunnels) {
	
	my $tun_name = $tun->name;
	my (@fwall_objs);
	
	@fwall_objs = $tun->firewall_rules;

	if (@fwall_objs) {push @local_fwallrule, @fwall_objs};
    }
    return Funknet::Config::FirewallRuleSet->new( firewall => \@local_fwallrule,
					    	  source  => 'whois' );
}
	
sub sessions {
    my ($self) = @_;
    my $w = $self->{_fwc};
    my $l = Funknet::ConfigFile::Tools->local;
    
    $w->type('route');
    $w->inverse_lookup('origin');

    my @route_objects = $w->query($l->{as});

    my @routes;
    for my $obj (@route_objects) {
        if (my $route = $obj->route) {
            push @routes, $route;
        }
    }

    if (scalar @routes) {
	debug("found ".(scalar @routes). " routes for $l->{as}");
    } else {
	$self->warn("no routes found for $l->{as}");
	return undef;
    }

    $w->type('aut-num');
    my $as = $w->query($l->{as});

    if (defined $as) {
	debug("loaded aut-num for $l->{as}");
    } else {
	$self->warn("aut-num not found for $l->{as}");
	return undef;
    }

    my $bgp = Funknet::Config::BGP->new( 
					local_as => $l->{as},
					routes  => \@routes,
					source => 'whois',
				       );

  SESSION: for my $tun_name ($as->tun) {
	
	$w->type('tunnel');
	my $tun = $w->query($tun_name);

	if (defined $tun) {
	    debug("loaded tunnel for $tun_name");
	} else {
	    $self->warn("tunnel object $tun_name missing?");
	    next SESSION;
	}
	
	for my $i ( 0..1 ) {
	    my @as = $tun->as;
	    my @ad = $tun->address;
	    my @ep = $tun->endpoint;
	
	    if ($as[$i] eq $l->{as}) {

		# check this is a session for our router 
		# by comparing endpoint.
		next SESSION unless (_is_current_endpoint($l, $ep[$i]));
		
		my $acl_in = Funknet::Config::AccessList->new( source_as   => $as[$i],
							       peer_as     => $as[1-$i],
							       source_addr => $ad[$i],
							       peer_addr   => $ad[1-$i],
							       dir         => 'import',
							       source      => 'whois',
                                                               order       => $i,
							     );
		
		my $acl_out = Funknet::Config::AccessList->new( source_as   => $as[$i],
								peer_as     => $as[1-$i],
								source_addr => $ad[$i],
								peer_addr   => $ad[1-$i],
								dir         => 'export',
								source      => 'whois',
                                                                order       => $i,
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

sub encryption {
    my ($self, $tun_set) = @_;
    my $w = $self->{_fwc};
    $w->type('tunnel');
    my @local_enc;

    foreach my $tun ($tun_set->tunnels) {
	my $whois_obj = $w->query($tun->name);

	# we get both encryption attributes, and compare
	# endpoints with the local endpoint to decide 
	# which one is ours.

	my @en = $whois_obj->encryption;
	my @ep = $whois_obj->endpoint;
	
	my $encr;
	if ($ep[0] eq $tun->local_endpoint()) {
	    $encr = $en[0];
	}
	if ($ep[1] eq $tun->local_endpoint()) {
	    $encr = $en[1];
	}

	if (defined $encr) {
	    my ($type, $param);
	    if ($encr =~ /^X509CERT-(.*)/) {
		$param = $1;

		if (ref $tun eq 'Funknet::Config::Tunnel::Linux') {
		    $type = 'ipsec';
		}
		if (ref $tun eq 'Funknet::Config::Tunnel::BSD') {
		    $type = 'ipsec';
		}
		if (ref $tun eq 'Funknet::Config::Tunnel::Solaris') {
		    $type = 'ipsec';
		}
		if (ref $tun eq 'Funknet::Config::Tunnel::IOS') {
		    $type = 'ipsec';
		}
		if (ref $tun eq 'Funknet::Config::Tunnel::OpenVPN') {
		    $type = 'openvpn';
		}
	    }

	    my $enc_obj = Funknet::Config::Encryption->new( tun    => $tun,
							    type   => $type,
							    param  => $param,
							    source => 'whois',
							  );
	    if (defined $enc_obj) {
		push @local_enc, $enc_obj;

		my $tun_data = $enc_obj->tun_data();
		if (defined $tun_data) {
		    $tun->enc_data($tun_data);
		}
	    }
	}
    }
    my $set = Funknet::Config::EncryptionSet->new( encryptions => \@local_enc,
						   source      => 'whois' );
    return $set;
}

sub _is_current_endpoint {
    my ($l, $ep) = @_;
    
    my @endpoints;
    if (ref $l->{endpoint}) {
	@endpoints = @{ $l->{endpoint} };
    } else {
	@endpoints = ($l->{endpoint});
    }
    for my $endpoint (@endpoints) {
	if ($endpoint eq $ep) {
	    return 1;
	}
    }
    return undef;
}

1;
