package Funknet::Config::BGP::IOS;
use strict;
use base qw/ Funknet::Config::BGP /;
use Network::IPv4Addr qw/ ipv4_cidr2msk /;

sub config {
    my ($self) = @_;
    my $l = Funknet::Config::ConfigFile->local;

    my $config = "router bgp $l->{as}\n";

    if (defined $self->{_routes} && ref $self->{_routes} eq 'ARRAY') {	
        for my $route (@{ $self->{_routes}}) {
            $config .= " network "._prefix_to_mask($route);
        }
    }	

    foreach my $neighbor (keys %{ $self->{_neighbors} }) {
	$config .= $self->{_neighbors}->{$neighbor}->config;
    }
    $config .= "!\n";

    foreach my $neighbor (keys %{ $self->{_neighbors} }) {
	my $n_obj = $self->{_neighbors}->{$neighbor};
	if (defined $n_obj->{_acl_in}) {
	    $config .= $n_obj->{_acl_in}->config;
	}
	if (defined $n_obj->{_acl_out}) {
	    $config .= $n_obj->{_acl_out}->config;
	}
    }
    return $config;
}

sub diff {
    my ($whois, $host) = @_;
    my $l = Funknet::Config::ConfigFile->local;
    my (@bounce_req, $bounce_all, $bgp_req);
    my @cmds;

    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
	warn "diff passed objects backwards";
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
		    push @bounce_req, $n->remote_addr;
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
	    defined $n->{_acl_in} && push @cmds, $n->{_acl_in}->config;
	    defined $n->{_acl_out} && push @cmds, $n->{_acl_out}->config;
	} else {
	    # there already; make a diff.
	    my $h_n = $host->neighbor($n);

	    if (defined $h_n->{_acl_in} && !defined $n->{_acl_in}) {
		push @cmds, "no route-map ".$h_n->{_acl_in}->name;
		push @cmds, "no ip prefix-list ".$h_n->{_acl_in}->name;
		push @bounce_req, $n->remote_addr;
	    }
	    if (defined $h_n->{_acl_out} && !defined $n->{_acl_out}) {
		push @cmds, "no route-map ".$h_n->{_acl_out}->name;
		push @cmds, "no ip prefix-list ".$h_n->{_acl_out}->name;
		push @bounce_req, $n->remote_addr;
	    }
	    if (defined $n->{_acl_in} && !defined $h_n->{_acl_in}) {
		push @cmds, "no route-map ".$n->{_acl_in}->name;
		push @cmds, "no ip prefix-list ".$n->{_acl_in}->name;
		push @cmds, $n->{_acl_in}->config;
		push @cmds, 'exit';
		push @bounce_req, $n->remote_addr;
	    }
	    if (defined $n->{_acl_out} && !defined $h_n->{_acl_out}) {
		push @cmds, "no route-map ".$n->{_acl_out}->name;
		push @cmds, "no ip prefix-list ".$n->{_acl_out}->name;
		push @cmds, $n->{_acl_out}->config;
		push @cmds, 'exit';
		push @bounce_req, $n->remote_addr;
	    }
	    if (defined $n->{_acl_in} && defined $h_n->{_acl_in}) {
		my @acl_diff = $n->{_acl_in}->diff($h_n->{_acl_in});
		for my $cmd (@acl_diff) {
		    if (defined $cmd) {
			push @cmds, $cmd;
			push @bounce_req, $n->remote_addr;
		    }
		}
	    }
	    if (defined $n->{_acl_out} && defined $h_n->{_acl_out}) {
		my @acl_diff = $n->{_acl_out}->diff($h_n->{_acl_out});
		for my $cmd (@acl_diff) {
		    if (defined $cmd) {
			push @cmds, $cmd;
			push @bounce_req, $n->remote_addr;
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
	push @cmds, map { "clear ip bgp $_" } @bounce_req;
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
