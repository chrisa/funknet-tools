package Funknet::Node::CNode;
use strict;
use base qw/ Funknet::Node /;

use Data::Dumper;
use NetAddr::IP;

sub new {
    my ($class, $nets, %args) = @_;
    my $self = bless {}, $class;

    my @whole_lot = @$nets;
    my @usable_nets;

    print STDOUT "CNode: $args{name}\n";
    foreach my $net (@whole_lot) {

	print STDOUT "Network: $net\n";

	my $net_ip_object = new NetAddr::IP $net;

	my $first_network_address = $net_ip_object->network->addr();
	my $last_broadcast_address = $net_ip_object->broadcast->addr();

	my $first_net_ip_object = new NetAddr::IP ("$first_network_address/30");
	my $last_net_ip_object = new NetAddr::IP ("$last_broadcast_address/30");

	my $first_net_object = $first_net_ip_object->network();
	my $last_net_object = $last_net_ip_object->network();

	print STDOUT "first net: $first_net_object\n";
	print STDOUT "last net: $last_net_object\n";
	print STDOUT "\n";

	my $counter = $net_ip_object->network();

	CHUG:	while ($counter->network() <= $last_net_object->network()) {
		my $this_net_address = $counter->addr();
		my $this_net = new NetAddr::IP("$this_net_address/30");
		push (@usable_nets, $this_net->network());
	
		$counter = ($counter + 4);
		last CHUG if ($counter < $this_net);
	}

    }

    print $#usable_nets+1 . " nets available\n\n";

    $self->{_transit_nets} = [ @usable_nets ];
    $self->{_name} = $args{name};
    $self->{_as}   = $args{as};
    $self->{_endpoint}   = $args{endpoint};
    $self->{_contact}   = $args{contact};
    $self->{_mntner}   = $args{mntner};

    return $self;
}

sub transitnets {
    my ($self) = @_;
    return @{ $self->{_transit_nets} };
}

1;
