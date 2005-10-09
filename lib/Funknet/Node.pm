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

    my $og = Funknet::Whois::ObjectGenerator->new( source  => $args{source},
						   mntner  => $mntner,
						   e_mail  => $args{changed},
						   person  => $contact,
						 );

    my $tunnel_obj = $og->tunnel(	'name'	   => "$cnode_name-$node_name",
				'as'	   => [ $cnode_as, $node_as ],
				'endpoint' => [ $cnode_endpoint, $node_endpoint ],
				'address' => [ $cnode_address, $node_address ],
				'type'    => $args{tunnel_type},
			     );
#print scalar $tunnel_obj->text . "\n";
#print Dumper $tunnel_obj;

    if ($tunnel_obj->error()) {
        return $tunnel_obj->error();
    }
    else{
        return $tunnel_obj->text();
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
