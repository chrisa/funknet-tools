package Funknet::Config::Tunnel::BSD;
use strict;
use base qw/ Funknet::Config::Tunnel /;

=head1 NAME

Funknet::Config::Tunnel::BSD

=head1 DESCRIPTION

This class contains methods for parsing, creating and deleting tunnel
interfaces on BSD. (BSD for these purposes includes Free, Net and
OpenBSD, plus Mac OSX). 

=head1 METHODS

=head2 config

Returns the configuration of the Tunnel object as text. This should be
in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 new_from_ifconfig

Reads a host interface description taken from ifconfig and parses the
useful information from it. Only 'gif' and 'gre' interfaces are
supported for BSD; other interface types cause this method to return
undef.

=head2 create

Returns a list of strings containing commands to configure a tunnel
interface on BSD. The interface details are passed in as part of
$self, and the new interface number is passed in as $inter. The
commands should assume that no interface with that number currently
exists.

=head2 delete

Returns a list of strings containing commands to unconfigure a tunnel
interface on BSD. The interface should be removed, not just put into
the 'down' state. 

=cut

sub config {
    my ($self) = @_;

    return 
	"BSD\n" .
	"$self->{_type}:\n" .
	"$self->{_local_endpoint} -> $self->{_remote_endpoint}\n" . 
	"$self->{_local_address} -> $self->{_remote_address}\n";
}

sub new_from_ifconfig {
    my ($class, $if) = @_;

    my $type;
    $if =~ /^(gif)(\d+)/ and $type = 'ipip';
    $if =~ /^(gre)(\d+)/ and $type = 'gre';
    my $interface = $2;
    my $ifname = "$1$2";
    defined $type or return undef;

    my ($local_endpoint, $remote_endpoint) = $if =~ /tunnel inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+)/;
    my ($local_address, $remote_address)   = $if =~ /inet (\d+\.\d+\.\d+\.\d+) -+> (\d+\.\d+\.\d+\.\d+) netmask/;

    return Funknet::Config::Tunnel->new(
	name => 'none',
	local_address => $local_address,
	remote_address => $remote_address,
	local_endpoint => $local_endpoint,
	remote_endpoint => $remote_endpoint,
	interface => $interface,
	type => $type,
	ifname => $ifname,
	local_os => 'bsd',
	source => 'host',
    );
}

sub delete {
    my ($self) = @_;

    my $tun_type;
    for ($self->{_type})
    {
	if    (/ipip/) {$tun_type = 'gif';}
	elsif (/gre/) {$tun_type = 'gre';}
    }

    return "ifconfig $tun_type$self->{_interface} destroy";
}

sub create {
    my ($self, $inter) = @_;

    my $tun_type;
    for ($self->{_type})
    {
	if    (/ipip/) {$tun_type = 'gif';}
	elsif (/gre/) {$tun_type = 'gre';}
    }
     
    return (
	"ifconfig $tun_type$inter create",
	"ifconfig $tun_type$inter tunnel $self->{_local_endpoint} $self->{_remote_endpoint}",
	"ifconfig $tun_type$inter inet $self->{_local_address} $self->{_remote_address} netmask 255.255.255.252"
     );
}

1;
