package Funknet::Config::Tunnel::BSD;
use strict;
use base qw/ Funknet::Config::Tunnel /;

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
    $if =~ /^gif/ and $type = 'ipip';
    $if =~ /^gre/ and $type = 'gre';
    defined $type or return undef;

    my ($local_endpoint, $remote_endpoint) = $if =~ /tunnel inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+)/;
    my ($local_address, $remote_address)   = $if =~ /inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+) netmask/;

    return Funknet::Config::Tunnel->new(
	name => 'none',
	local_address => $local_address,
	remote_address => $remote_address,
	local_endpoint => $local_endpoint,
	remote_endpoint => $remote_endpoint,
	type => $type,
	local_os => 'bsd',
	source => 'host',
    );
}

sub delete {
    my ($self) = @_;
    return "a list of commands to delete $self->{_interface} on BSD go here";
}

sub create {
    my ($self, $inter) = @_;
    # details are in $self, see Solaris.pm
    return "a list of commands to create a tunnel interface numbered $inter on BSD go here";
}

1;
