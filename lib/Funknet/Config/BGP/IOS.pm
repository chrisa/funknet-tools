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


package Funknet::Config::BGP::IOS;
use strict;
use base qw/ Funknet::Config::BGP /;
use Network::IPv4Addr qw/ ipv4_cidr2msk /;

sub config {
    my ($self) = @_;
    my $l = Funknet::Config::ConfigFile->local;
    $l->{as} =~ s/^AS//;
    
    my @cmds;
    push @cmds, "router bgp $l->{as}";

    if (defined $self->{_routes} && ref $self->{_routes} eq 'ARRAY') {	
        for my $route (@{ $self->{_routes}}) {
            push @cmds, " network "._prefix_to_mask($route);
        }
    }	

    foreach my $neighbor (keys %{ $self->{_neighbors} }) {
	push @cmds, $self->{_neighbors}->{$neighbor}->config;
    }

    foreach my $neighbor (keys %{ $self->{_neighbors} }) {
	my $n_obj = $self->{_neighbors}->{$neighbor};
	if (defined $n_obj->{_acl_in}) {
	    push @cmds, $n_obj->{_acl_in}->config;
	}
	if (defined $n_obj->{_acl_out}) {
	    push @cmds, $n_obj->{_acl_out}->config;
	}
    }
    return @cmds;
}

sub diff {
    my ($whois, $host) = @_;
    my $l = Funknet::Config::ConfigFile->local;
    $l->{as} =~ s/^AS//;

    my ($bounce_req, $bounce_all, $bgp_req);
    my @cmds;

    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
	$whois->warn("diff passed objects backwards");
	return undef;
    }

    # see what we need to do to the 'network' statements
    
    for my $r ( $whois->routes ) {
	unless ($host->route_set($r) ) {
	    push @cmds, "network "._prefix_to_mask($r);
	    $bounce_all = 1;
	    $bgp_req = 1;
	}
    }
    for my $r ( $host->routes ) {
	unless ($whois->route_set($r) ) {
	    push @cmds, "no network "._prefix_to_mask($r);
	    $bounce_all = 1;
	    $bgp_req = 1;
	}
    }

    # iterate neighbors, do add/remove/change.
    
    for my $n ( $whois->neighbors ) {
	unless ($host->neighbor_set($n) ) {
	    # not there; config from scratch.
	    push @cmds, $n->config;
	    $bgp_req = 1;
	} else {
	    # there already; make a diff (careful not to push undefs)
	    my @neighbor_diff = $n->diff($host->neighbor($n));
	    for my $cmd (@neighbor_diff) {
		if (defined $cmd) {
		    push @cmds, $cmd;
		    $bounce_req->{$n->remote_addr} = 1;
		    $bgp_req = 1;
		}
	    }
	}
    }
    for my $n ( $host->neighbors ) {
	unless ($whois->neighbor_set($n) ) {
	    # not there; delete.
	    push @cmds, "no neighbor ".$n->remote_addr;
	    $bgp_req = 1;
	}
    }
    
    # we're done with bgp, get back to configuration mode
    
    if ($bgp_req) {
	unshift @cmds, 'router bgp '.$l->{as};
	push @cmds, 'exit';
    }

    # see if we need to change the AS on the bgp-router first
    if (defined $host->local_as && $host->local_as != $whois->local_as) {
	unless ($host->local_as eq '00000') {
	    unshift @cmds, "no router bgp ".$host->local_as;
	}
    }

    # iterate acls, do add/remove/change - doing delete first!

    for my $n ( $host->neighbors ) {
	unless ($whois->neighbor_set($n) ) {
	    # not there; delete.
	    defined $n->{_acl_in} && push @cmds, "no route-map ".$n->{_acl_in}->name;
	    defined $n->{_acl_in} && push @cmds, "no ip prefix-list ".$n->{_acl_in}->name;
	    defined $n->{_acl_out} && push @cmds, "no route-map ".$n->{_acl_out}->name;
	    defined $n->{_acl_out} && push @cmds, "no ip prefix-list ".$n->{_acl_out}->name;
	}
    }

    for my $n ( $whois->neighbors ) {
	unless ($host->neighbor_set($n) ) {
	    # not there; config from scratch (deleting first just in case)
	    defined $n->{_acl_in} && push @cmds, "no route-map ".$n->{_acl_in}->name;
	    defined $n->{_acl_in} && push @cmds, "no ip prefix-list ".$n->{_acl_in}->name;
	    defined $n->{_acl_out} && push @cmds, "no route-map ".$n->{_acl_out}->name;
	    defined $n->{_acl_out} && push @cmds, "no ip prefix-list ".$n->{_acl_out}->name;
	    defined $n->{_acl_in} && push @cmds, $n->{_acl_in}->config, 'exit';
	    defined $n->{_acl_out} && push @cmds, $n->{_acl_out}->config, 'exit';
	} else {
	    # there already; make a diff.
	    my $h_n = $host->neighbor($n);

	    if (defined $h_n->{_acl_in} && !defined $n->{_acl_in}) {
		push @cmds, "no route-map ".$h_n->{_acl_in}->name;
		push @cmds, "no ip prefix-list ".$h_n->{_acl_in}->name;
		$bounce_req->{$n->remote_addr} = 1;
	    }
	    if (defined $h_n->{_acl_out} && !defined $n->{_acl_out}) {
		push @cmds, "no route-map ".$h_n->{_acl_out}->name;
		push @cmds, "no ip prefix-list ".$h_n->{_acl_out}->name;
		$bounce_req->{$n->remote_addr} = 1;
	    }
	    if (defined $n->{_acl_in} && !defined $h_n->{_acl_in}) {
		push @cmds, "no route-map ".$n->{_acl_in}->name;
		push @cmds, "no ip prefix-list ".$n->{_acl_in}->name;
		push @cmds, $n->{_acl_in}->config;
		push @cmds, 'exit';
		$bounce_req->{$n->remote_addr} = 1;
	    }
	    if (defined $n->{_acl_out} && !defined $h_n->{_acl_out}) {
		push @cmds, "no route-map ".$n->{_acl_out}->name;
		push @cmds, "no ip prefix-list ".$n->{_acl_out}->name;
		push @cmds, $n->{_acl_out}->config;
		push @cmds, 'exit';
		$bounce_req->{$n->remote_addr} = 1;
	    }
	    if (defined $n->{_acl_in} && defined $h_n->{_acl_in}) {
		my @acl_diff = $n->{_acl_in}->diff($h_n->{_acl_in});
		for my $cmd (@acl_diff) {
		    if (defined $cmd) {
			push @cmds, $cmd;
			$bounce_req->{$n->remote_addr} = 1;
		    }
		}
	    }
	    if (defined $n->{_acl_out} && defined $h_n->{_acl_out}) {
		my @acl_diff = $n->{_acl_out}->diff($h_n->{_acl_out});
		for my $cmd (@acl_diff) {
		    if (defined $cmd) {
			push @cmds, $cmd;
			$bounce_req->{$n->remote_addr} = 1;
		    }
		}
	    }
	}
    }


    # we're done in configuration mode, get back to enable.
    
    if (scalar @cmds) {
	unshift @cmds, 'configure terminal';
	push @cmds, 'exit';
    }

    # bounce the relevant bgp sessions (i.e. changed route-maps)

    if ( $bounce_all ) {
	push @cmds, 'clear ip bgp *';
    } else {
	push @cmds, map { "clear ip bgp $_" } keys %$bounce_req;
    }

    return @cmds;
}

sub _prefix_to_mask {
    my ($prefix) = @_;
    my ($network, $len) = $prefix =~ /^(.+)\/(.+)$/;
    my $mask = ipv4_cidr2msk( $len ); 

    return "$network mask $mask";
}
1;
