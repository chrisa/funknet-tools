package Funknet::Config::TunnelSet;
use strict;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    $self->{_tunnels} = $args{tunnels};
    
    return $self;
}

sub tunnels {
    my ($self) = @_;
    return $self->{_tunnels};
}

sub config {
    my ($self) = @_;
    
    for my $tun (@{$self->{_tunnels}}) {
	print $tun->config;
	print "\n";
    }
}

1;
