package Funknet::Config::Tunnel::Solaris;
use strict;
use base qw/ Funknet::Config::Tunnel /;

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

1;
