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
    my $acl_in = Funknet::Config::AccessList->new( source_as   => $self->{_local_as},
						   peer_as     => $args{remote_as},
						   source_addr => $args{local_addr},
						   peer_addr   => $args{remote_addr},
						   dir         => 'import',
						   source      => $args{source},
						   local_router => $self->{_local_router},
						 );

    my $acl_out = Funknet::Config::AccessList->new( source_as   => $self->{_local_as},
						    peer_as     => $args{remote_as},
						    source_addr => $args{local_addr},
						    peer_addr   => $args{remote_addr},
						    dir         => 'export',
						    source      => $args{source},
						    local_router => $self->{_local_router},
						  );
    my ($acl_in_name, $acl_out_name);
    if (defined $acl_in) {
	push @{$self->{_acls}}, $acl_in;
	$acl_in_name = $acl_in->name;
    }
    if (defined $acl_out) {
	push @{$self->{_acls}}, $acl_out;
	$acl_out_name = $acl_out->name;
    }
	
    my $session = Funknet::Config::Neighbor->new( remote_as   => $args{remote_as},
						  remote_addr => $args{remote_addr},
						  description => $args{description},
						  source      => $self->{_source},
						  acl_in      => $acl_in_name,
						  acl_out     => $acl_out_name,
						);
    if (defined $session) {
	push @{$self->{_neighbors}}, $session;
    }
}

1;
