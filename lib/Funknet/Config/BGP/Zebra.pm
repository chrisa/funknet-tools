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

    foreach my $neighbor (@{ $self->{_neighbors} }) {
	$config .= $neighbor->config;
    }
    $config .= "!\n";

    foreach my $neighbor (@{ $self->{_neighbors} }) {
	if (defined $neighbor->{acl_in}) {
	    $config .= $neighbor->{acl_in}->config;
	}
	if (defined $neighbor->{acl_out}) {
	    $config .= $neighbor->{acl_out}->config;
	}
    }
    return $config;
}
    
1;
