package Funknet::Config::Tunnel::IOS;
use strict;
use base qw/ Funknet::Config::Tunnel /;

sub config {
    my ($self) = @_;

    return 
	"IOS\n" .
	"$self->{_type}:\n" .
	"$self->{_local_endpoint} -> $self->{_remote_endpoint}\n" . 
	"$self->{_local_address} -> $self->{_remote_address}\n";
}

1;
