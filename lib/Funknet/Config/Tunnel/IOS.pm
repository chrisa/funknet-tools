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

# these methods return commands which need enable mode.

sub delete {
    my ($self) = @_;
    return "no interface Tunnel$self->{_interface}";
}

sub create {
    my ($self, $inter) = @_;
    
    return (
	"interface Tunnel$inter",
        " tunnel mode $self->{_type}", 
	" tunnel source $self->{_local_endpoint}",
	" tunnel destination $self->{_remote_endpoint}",
	" ip address $self->{_local_address} 255.255.255.252" );
}

1;
