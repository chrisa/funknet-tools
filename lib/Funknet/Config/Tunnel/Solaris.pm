package Funknet::Config::Tunnel::Solaris;
use strict;
use base qw/ Funknet::Config::Tunnel /;

=head1 NAME

Funknet::Config::Tunnel::Solaris

=head1 DESCRIPTION

This class contains methods for parsing, creating and deleting tunnel
interfaces on Solaris.

=head1 METHODS

=head2 config

Returns the configuration of the Tunnel object as text. This should be
in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 new_from_ifconfig

Reads a host interface description taken from ifconfig and parses the
useful information from it. Only 'ip.tun' (equivalent to BSD 'gif')
interfaces are supported for Solaris; other interface types cause this
method to return undef.

=head2 create

Returns a list of strings containing commands to configure a tunnel
interface on Solaris. The interface details are passed in as part of
$self, and the new interface number is passed in as $inter. The
commands should assume that no interface with that number currently
exists.

=head2 delete

Returns a list of strings containing commands to unconfigure a tunnel
interface on Solaris. The interface should be removed
(i.e. unplumbed), not just put into the 'down' state.

=cut

sub config {
    my ($self) = @_;

    return 
	"Solaris\n" .
	"$self->{_type}:\n" .
	"$self->{_local_endpoint} -> $self->{_remote_endpoint}\n" . 
	"$self->{_local_address} -> $self->{_remote_address}\n";
}

sub new_from_ifconfig {
    my ($class, $if) = @_;

    my $type;
    $if =~ /^ip.tun/ and $type = 'ipip';
    defined $type or return undef;

    my ($local_endpoint, $remote_endpoint) 
	= $if =~ /inet tunnel src (\d+\.\d+\.\d+\.\d+) +tunnel dst (\d+\.\d+\.\d+\.\d+)/;
    my ($local_address, $remote_address)
	= $if =~ /inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+)/;

    return Funknet::Config::Tunnel->new(
	name => 'none',
	local_address => $local_address,
	remote_address => $remote_address,
	local_endpoint => $local_endpoint,
	remote_endpoint => $remote_endpoint,
	type => $type,
	local_os => 'solaris',
	source => 'host',
    );
}

sub delete {
    my ($self) = @_;
    return "ifconfig $self->{_interface} inet unplumb";
}

sub create {
    my ($self, $inter) = @_;
    return (
	"ifconfig ip.tun$inter inet plumb",
	"ifconfig ip.tun$inter tsrc $self->{_local_endpoint} tdst $self->{_remote_endpoint}",
	"ifconfig ip.tun$inter $self->{_local_address} $self->{_remote_address}",
	"ifconfig ip.tun$inter netmask 255.255.255.252" );
}



1;
