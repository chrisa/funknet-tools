package Funknet::Config::BGP::IOS;
use strict;
use base qw/ Funknet::Config::BGP /;

sub config {
    my ($self) = @_;
    
    my $config = "router bgp $self->{_local_as}\n";

    if (defined $self->{_routes} && ref $self->{_routes} eq 'ARRAY') {	
        for my $route (@{ $self->{_routes}}) {
            $config .= " network $route ! amend this for IOS\n";
        }
    }	

    foreach my $neighbor (@{ $self->{_neighbors} }) {
	$config .= $neighbor->config;
    }
    $config .= "!\n";

    foreach my $neighbor (@{ $self->{_neighbors} }) {
	if (defined $neighbor->{_acl_in}) {
	    $config .= $neighbor->{_acl_in}->config;
	}
	if (defined $neighbor->{_acl_out}) {
	    $config .= $neighbor->{_acl_out}->config;
	}
    }
    return $config;
}
    
1;
