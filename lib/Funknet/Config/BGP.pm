package Funknet::Config::BGP;
use strict;
use Funknet::Config::Validate qw/ is_valid_os is_valid_as is_valid_router /;
use Funknet::Config::AccessList;    
use Funknet::Config::Neighbor;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'ifconfig')) {
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

#     unless (defined $args{local_os} && is_valid_os($args{local_os})) {
# 	warn "missing local_os";
# 	return undef;
#     } else {
# 	$self->{_local_os} = $args{local_os};
#     }

#     unless (defined $args{local_router} && is_valid_router($args{local_router})) {
# 	warn "missing local_router";
# 	return undef;
#     } else {
# 	$self->{_local_router} = $args{local_router};
#     }
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
						 );

    my $acl_out = Funknet::Config::AccessList->new( source_as   => $self->{_local_as},
						    peer_as     => $args{remote_as},
						    source_addr => $args{local_addr},
						    peer_addr   => $args{remote_addr},
						    dir         => 'export',
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

sub config {
    my ($self) = @_;
    
    my $config = "router bgp $self->{_local_as}\n";

    foreach my $neighbor (@{ $self->{_neighbors} }) {
	$config .= $neighbor->config;
    }
    $config .= "!\n";

    foreach my $acl (@{ $self->{_acls} }) {
	$config .= $acl->config;
    }
    return $config;
}
    

1;
