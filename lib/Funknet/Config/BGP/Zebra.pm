package Funknet::Config::BGP::Zebra;
use strict;
use base qw/ Funknet::Config::BGP /;

sub config {
    my ($self) = @_;
    
    my $config = "router bgp $self->{_local_as}\n";

    if (defined $self->{_routes} && ref $self->{_routes} eq 'ARRAY') {	
        for my $route (@{ $self->{_routes}}) {
            $config .= " network $route\n";
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
    my @cmds;

    my (@bounce_req, $bounce_all);
    
    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
	warn "diff passed objects backwards";
	return undef;
    }
    
    # see if we need to change the AS on the bgp-router first
    if (defined $host->local_as && $host->local_as != $whois->local_as) {
	push @cmds, "no router bgp ".$host->local_as;
    }
    push @cmds, "router bgp ".$whois->local_as;
    
    # see what we need to do to the 'network' statements
    
    for my $r ( $whois->routes ) {
	unless ($host->route_set($r) ) {
	    push @cmds, "network $r";
	}
	$bounce_all = 1;
    }
    for my $r ( $host->routes ) {
	unless ($whois->route_set($r) ) {
	    push @cmds, "no network $r";
	}
	$bounce_all = 1;
    }

    # iterate neighbors, do add/remove/change.
    
    for my $n ( $whois->neighbors ) {
	unless ($host->neighbor_set($n) ) {
	    # not there; config from scratch.
	    push @cmds, $n->config;
	} else {
	    # there already; make a diff.
	    push @cmds, $n->diff($host->neighbor($n));
	    push @bounce_req, $n->remote_addr;
	}
    }
    for my $n ( $host->neighbors ) {
	unless ($whois->neighbor_set($n) ) {
	    # not there; delete.
	    push @cmds, "no neighbor ".$n->remote_addr;
	}
    }

    # iterate acls, do add/remove/change

    for my $n ( $whois->neighbors ) {
	unless ($host->neighbor_set($n) ) {
	    # not there; config from scratch.
	    defined $n->{_acl_in} && push @cmds, $n->{_acl_in}->config;
	    defined $n->{_acl_out} && push @cmds, $n->{_acl_out}->config;
	} else {
	    # there already; make a diff.
	    my $h_n = $host->neighbor($n);
	    if (defined $n->{_acl_in} && !defined $h_n->{acl_in}) {
		push @cmds, $n->{_acl_in}->config;
	    }
	    if (defined $n->{_acl_out} && !defined $h_n->{acl_out}) {
		push @cmds, $n->{_acl_out}->config;
	    }
	    if (defined $h_n->{_acl_in} && !defined $n->{acl_in}) {
		push @cmds, $h_n->{_acl_in}->config;
	    }
	    if (defined $h_n->{_acl_out} && !defined $n->{acl_out}) {
		push @cmds, $h_n->{_acl_out}->config;
	    }
	    if (defined $n->{_acl_in} && defined $h_n->{_acl_in}) {
		push @cmds, $n->{_acl_in}->diff($h_n->{_acl_in});
	    }
	    if (defined $n->{_acl_out} && defined $h_n->{_acl_out}) {
		push @cmds, $n->{_acl_out}->diff($h_n->{_acl_out});
	    }
	}
	push @bounce_req, $n->remote_addr;
    }
    for my $n ( $host->neighbors ) {
	unless ($whois->neighbor_set($n) ) {
	    # not there; delete.
	    defined $n->{_acl_in} && push @cmds, "no route-map ".$n->{acl_in}->name;
	    defined $n->{_acl_in} && push @cmds, "no ip prefix-list ".$n->{acl_in}->name;
	    defined $n->{_acl_out} && push @cmds, "no route-map ".$n->{acl_out}->name;
	    defined $n->{_acl_out} && push @cmds, "no ip prefix-list ".$n->{acl_out}->name;
	    push @bounce_req, $n->remote_addr;
	}
    }

    push @cmds, map { "clear ip bgp $_" }, @bounce_req;
    $bounce_all and push @cmds, 'clear ip bgp *';

    return @cmds;
}

1;
