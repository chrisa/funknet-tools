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

    

1;
