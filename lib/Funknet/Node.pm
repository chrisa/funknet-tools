package Funknet::Node;
use strict;

use Funknet::Node::Node;
use Funknet::Node::CNode;
use Funknet::Whois::ObjectGenerator;

use base qw/ Funknet /;
use Data::Dumper;
use NetAddr::IP;

sub new_tunnel {
    my ($class, $cnode, $node, $transit_net) = @_;
    my $self = bless {}, $class;

    #Get 1st Address
    $transit_net++;

    my $cnode_name = $cnode->name;
    my $cnode_as = $cnode->as;
    my $cnode_endpoint = $cnode->endpoint;
    my $cnode_address = $transit_net->addr();
    my $contact = $cnode->contact;
    my $mntner = $cnode->mntner;

    #Get 2nd Address
    $transit_net++;
    
    my $node_name = $node->name;
    my $node_as = $node->as;
    my $node_endpoint = $node->endpoint;
    my $node_address = $transit_net->addr();

#    my $gen = Funknet::Whois::ObjectGenerator->new( 'source' => 'FUNKNET',
#						    'mntner' => $mntner,
#						    'person' => $contact,
#						    'e_mail' => $update_to,
#						  );

    return ("tunnel:\t\t$cnode_name-$node_name\n" . 
	     "as:\t\t$cnode_as\n" .
	     "as:\t\t$node_as\n" .
	     "endpoint:\t$cnode_endpoint\n" .
	     "endpoint:\t$node_endpoint\n" .
	     "address:\t$cnode_address\n" .
	     "address:\t$node_address\n" .
	     "admin-c:\t$contact\n" . 
	     "tech-c:\t\t$contact\n" .
	     "mnt-by:\t\t$mntner\n");
}

sub as {
    my ($self) = @_;
    return $self->{_as};
}

sub name {
    my ($self) = @_;
    return $self->{_name};
}

sub endpoint {
    my ($self) = @_;
    return $self->{_endpoint};
}

sub contact {
    my ($self) = @_;
    return $self->{_contact};
}

sub mntner {
    my ($self) = @_;
    return $self->{_mntner};
}

1;
