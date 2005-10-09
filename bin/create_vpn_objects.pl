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
my @autnums;

my @required_node_values = qw/ endpoint mntner name networks /;
my @required_cnode_values = qw/ endpoint mntner name transit_networks /;

my $person = 'VPN-CONTACT';
my $mntner = 'VPN-MNT';
my $create_email = 'dunc@bleh.org';
my $source = 'FUNKNET';
my $tunnel_type = 'ipip';

my $first_as = 61000;

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
						contact => $person,
						mntner => $cnode->{mntner},
					        as   => "AS$next_as",);
    push (@cnode_objects, $new_cnode);
    $next_as++;
}


for my $node (@$node_list) {

    my $new_node = Funknet::Node::Node->new(	$node->{networks},
						name => $node->{name},
						endpoint => $node->{endpoint},
						contact => $person,
						mntner => $node->{mntner},
						as   => "AS$next_as",);
    push (@node_objects, $new_node);
    $next_as++;
}

# Iterate through Cnode->Node combinations

for my $cnode (@cnode_objects) {
    for my $node (@node_objects) {
	my $transit_net = $cnode->next_transit_net;
	my $tunnel = Funknet::Node->new_tunnel(cnode	   => $cnode,
					       node	   => $node,
					       transit_net => $transit_net,
					       changed     => $create_email,
					       source	   => $source,
					       tunnel_type => $tunnel_type
						);
	print $tunnel . "\n\n";
	push (@tunnels, $tunnel);
    }
}


