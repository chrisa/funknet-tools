package Funknet::Config::BGP;
use strict;
use Funknet::Config::Validate qw/ is_valid_os is_valid_as is_valid_router /;
use Funknet::Config::AccessList;    
use Funknet::Config::Neighbor;
use Funknet::Config::BGP::IOS;
use Funknet::Config::BGP::Zebra;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'host')) {
	warn "missing source";
	return undef;
    } else {
	$self->{_source} = $args{source};
    }

    unless (defined $args{local_as} && is_valid_as($args{local_as})) {
	warn "missing local_as";
	return undef;
    } else {
        my $asno = $args{local_as};
        $asno =~ s/^AS//;
	$self->{_local_as} = $asno;
    }

    unless (defined $args{routes} && ref $args{routes} eq 'ARRAY') {
	warn "no routes";
        $self->{_routes} = [];
    } else {
        $self->{_routes} = $args{routes}; 
    }

    $args{local_router} eq 'ios' and 
	bless $self, 'Funknet::Config::BGP::IOS';
    $args{local_router} eq 'zebra' and 
	bless $self, 'Funknet::Config::BGP::Zebra';

    return $self;
}

sub add_session {
    my ($self, %args) = @_;

    $args{remote_as} =~ s/^AS//;

    my $session = Funknet::Config::Neighbor->new( remote_as   => $args{remote_as},
						  remote_addr => $args{remote_addr},
						  description => $args{description},
						  source      => $self->{_source},
						  acl_in      => $args{acl_in},
						  acl_out     => $args{acl_out},
						);
    if (defined $session) {
	$self->{_neighbors}->{$args{remote_addr}} = $session;
    }
}

# accessors

sub source {
    my ($self) = @_;
    return $self->{_source};
}
sub local_as {
    my ($self) = @_;
    return $self->{_local_as};
}
sub routes {
    my ($self) = @_;
    return wantarray?@{$self->{_routes}}:$self->{_routes};
}
sub route_set {
    my ($self, $route) = @_;
    unless (defined $self->{_route_hash}) {
	for (@{$self->{_routes}}) {
	    $self->{_route_hash}->{$_} = 1;
	}
    }
    return 1
	if defined $self->{_route_hash}->{$route};
    return undef;
}
sub neighbors {
    my ($self) = @_;
    my @n = map { $self->{_neighbors}->{$_} } keys %{ $self->{_neighbors} };
}
sub neighbor_set {
    my ($self, $neighbor) = @_;
    return (defined $self->{_neighbors}->{$neighbor->remote_addr})?1:0;
}
sub neighbor {
    my ($self, $n) = @_;
    return $self->{_neighbors}->{$n->remote_addr};
}

1;
