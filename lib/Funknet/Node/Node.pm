package Funknet::Node::Node;
use strict;
use base qw/ Funknet::Node /;

use Data::Dumper;

sub new {
    my ($class, $nets, %args) = @_;
    my $self = bless {}, $class;

    $self->{_nets} = @$nets;
    $self->{_name} = $args{name};
    $self->{_as}   = $args{as};
    $self->{_endpoint}   = $args{endpoint};
    $self->{_contact}   = $args{contact};
    $self->{_mntner}   = $args{mntner};
    
    return $self;
}

1;
