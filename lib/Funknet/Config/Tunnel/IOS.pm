package Funknet::Config::Tunnel::IOS;
use strict;
use base qw/ Funknet::Config::Tunnel /;

=head1 NAME

Funknet::Config::Tunnel::IOS

=head1 DESCRIPTION

This class contains methods for parsing, creating and deleting tunnel
interfaces on IOS.

=head1 METHODS

=head2 config

Returns the configuration of the Tunnel object as text. This should be
in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 new_from_ifconfig

Not present in this module. See CLI/IOS.pm

=head2 create

Returns a list of strings containing commands to configure a tunnel
interface on IOS. The interface details are passed in as part of
$self, and the new interface number is passed in as $inter. The
commands should assume that no interface with that number currently
exists.

=head2 delete

Returns a list of strings containing commands to unconfigure a tunnel
interface on IOS. The interface should be removed, not just put into
the 'down' state.

=cut

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
    return (
	"configure terminal",
	"no interface Tunnel$self->{_interface}",
	"exit" );
}

sub create {
    my ($self, $inter) = @_;
    
    return (
	"configure terminal",
	"interface Tunnel$inter",
        "tunnel mode $self->{_type}", 
	"tunnel source $self->{_local_endpoint}",
	"tunnel destination $self->{_remote_endpoint}",
	"ip address $self->{_local_address} 255.255.255.252",
        "exit" );
}

1;
