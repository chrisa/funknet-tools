package Funknet::Config::BGP::IOS;
use strict;
use base qw/ Funknet::Config::BGP /;
use Data::Dumper;

sub config {
    my ($self) = @_;
    
    my $config = "router bgp $self->{_local_as}\n";

    if (defined $self->{_routes} && ref $self->{_routes} eq 'ARRAY') {	
        for my $route (@{ $self->{_routes}}) {
            $config .= " network $route ! amend this for IOS\n";
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
	    push @cmds, "network $r ! modify this for IOS";
	}
    }
    for my $r ( $host->routes ) {
	unless ($whois->route_set($r) ) {
	    push @cmds, "no network $r ! modify this for IOS";
	}
    }

    # iterate neighbors, do add/remove/change.
    
    for my $n ( $whois->neighbors ) {
	unless ($host->neighbor_set($n) ) {
	    # not there; config from scratch.
	    push @cmds, $n->config;
	} else {
	    # there already; make a diff.
	    push @cmds, $n->diff($host->neighbor($n));
	}
    }
    for my $n ( $host->neighbors ) {
	unless ($whois->neighbor_set($n) ) {
	    # not there; delete.
	    push @cmds, "no neighbor ".$n->remote_as;
	}
    }

    return @cmds;
}

1;
