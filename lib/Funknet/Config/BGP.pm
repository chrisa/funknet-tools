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

1;
