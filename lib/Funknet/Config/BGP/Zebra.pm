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

    foreach my $acl (@{ $self->{_acls} }) {
	$config .= $acl->config;
    }
    return $config;
}
    
1;
