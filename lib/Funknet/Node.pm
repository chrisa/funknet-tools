package Funknet::Node;
use strict;

use Funknet::Node::Node;
use Funknet::Node::CNode;
use Funknet::Whois::ObjectGenerator;

use base qw/ Funknet /;
use Data::Dumper;
use NetAddr::IP;

sub new_tunnel {
    my ($class, %args) = @_;

    #Get 1st Address
    $args{transit_net}++;

    my $cnode_name = $args{cnode}->name;
    my $cnode_as = $args{cnode}->as;
    my $cnode_endpoint = $args{cnode}->endpoint;
    my $cnode_address = $args{transit_net}->addr();
    my $contact = $args{cnode}->contact;
    my $mntner = $args{cnode}->mntner;

    #Get 2nd Address
    $args{transit_net}++;
    
    my $node_name = $args{node}->name;
    my $node_as = $args{node}->as;
    my $node_endpoint = $args{node}->endpoint;
    my $node_address = $args{transit_net}->addr();

    # turn this into a FW::Object, for validation and pretty printing. 
    my $obj = Funknet::Whois::Object->new("tunnel:  $cnode_name-$node_name\n" . 
                                          "as:  $cnode_as\n" .
                                          "as:  $node_as\n" .
                                          "endpoint: $cnode_endpoint\n" .
                                          "endpoint: $node_endpoint\n" .
                                          "address: $cnode_address\n" .
                                          "address: $node_address\n" .
                                          "admin-c: $contact\n" . 
                                          "tech-c:  $contact\n" .
                                          "changed: $args{changed}\n" .
                                          "source:  $args{source}\n" .
                                          "type:    $args{tunnel_type}\n" .
                                          "mnt-by:  $mntner\n");
    if ($obj->error()) {
        return $obj->error();
    }
    else{
        return $obj->text();
    }
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
