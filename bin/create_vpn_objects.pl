#!/usr/bin/perl -w

use strict;
use Data::Dumper;

use lib './lib';
use Funknet::Node;

my %networks;
my %transit_networks;

my @node_objects;
my @cnode_objects;
my @tunnels;

my @required_node_values = qw/ endpoint mntner name networks /;
my @required_cnode_values = qw/ endpoint mntner name transit_networks /;


my $contact = 'VPN-CONTACT';
my $mntner = 'VPN-MNT';

my $first_as = 66000;

my $node_list = [
    {	name => 'nodeA', networks => [ '192.168.10.0/24' ],
	endpoint => '1.2.3.4', mntner => 'NODEA-MNT' },

    {	name => 'nodeB', networks => [ '192.168.11.0/24' ],
	endpoint => '5.6.7.8', mntner => 'NODEB-MNT' },

    {	name => 'nodeC', networks => [ '192.168.12.0/24', '192.168.13.0/24' ],
	endpoint => '9.5.3.4', mntner => 'NODEC-MNT' },
];

my $cnode_list = [
    {	name => 'CnodeA', transit_networks => [ '10.100.1.0/24' ],
	endpoint => '1.1.1.1', mntner => 'CNODEA-MNT' },

    {	name => 'CnodeB', transit_networks => [ '10.100.2.0/29', '10.100.3.0/24' ],
	endpoint => '2.2.2.2', mntner => 'CNODEB-MNT' },

];


#######################################################################

for my $cnode (@$cnode_list) {
    for my $key (@required_cnode_values) {
	die "Missing value $key for CNode $cnode" unless defined $cnode->{$key};
    }
}

for my $node (@$node_list) {
    for my $key (@required_node_values) {
	die "Missing value $key for Node $node" unless defined $node->{$key};
    }
}


my $next_as = $first_as;

for my $cnode (@$cnode_list) {

    my $new_cnode = Funknet::Node::CNode->new(	$cnode->{transit_networks},
					        name => $cnode->{name},
						endpoint => $cnode->{endpoint},
						contact => $contact,
						mntner => $cnode->{mntner},
					        as   => $next_as,);
    push (@cnode_objects, $new_cnode);
    $next_as++;
}


for my $node (@$node_list) {

    my $new_node = Funknet::Node::Node->new(	$node->{networks},
						name => $node->{name},
						endpoint => $node->{endpoint},
						contact => $contact,
						mntner => $node->{mntner},
						as   => $next_as,);
    push (@node_objects, $new_node);
    $next_as++;
}

# Iterate through Cnode->Node combinations

for my $cnode (@cnode_objects) {

    my @transit_nets = $cnode->transitnets;
    
    for my $node (@node_objects) {
	my $transit_net = shift(@transit_nets);
	my $tunnel = Funknet::Node->new_tunnel($cnode, $node, $transit_net);
	print "$tunnel\n";
	push (@tunnels, $tunnel);
    }
}


