package Funknet::Config::Host;
use strict;
use Funknet::Config::Tunnel;
use Funknet::Config::BGP;
use Funknet::Config::CLI;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    if (defined $args{local_as}) {
	$self->{_local_as} = $args{local_as};
    }
    if (defined $args{local_os}) {
	$self->{_local_os} = $args{local_os};
    }
    if (defined $args{local_router}) {
	$self->{_local_router} = $args{local_router};
    }
    if (defined $args{local_host}) {
	$self->{_local_host} = $args{local_host};
    }

    return $self;
}

sub tunnels {
    my ($self) = @_;
    my @local_tun;

    # special case of cisco needing CLI module
    if ($self->{_local_os} eq 'ios') {

	my $cli = Funknet::Config::CLI->new( local_host => $self->{_local_host},
					     local_router => $self->{_local_router} 
					   );
	$cli->get_interfaces;
	
	for my $if ($cli->interfaces) {
	    next unless $if->is_tun;
	    push @local_tun,
	    Funknet::Config::Tunnel->new(
		name => $if->description,
		local_address => $if->local_address,
		remote_address => $if->remote_address,
		local_endpoint => $if->local_endpoint,
		remote_endpoint => $if->remote_endpoint,
		type => $if->type,
		local_os => $self->{_local_os},
		source => 'host',
	    );
	}

    } else {
	
	# list of interface specs -- actually portable!
	my $c = `/sbin/ifconfig -a`;
	my @if = split /(?=^[a-z])/m,$c;

	for my $if (@if) {

	    warn "considering: $if";

	    chomp $if;
	    my $tun = Funknet::Config::Tunnel->new_from_ifconfig( $if, $self->{_local_os} );
	    if (defined $tun) {
		push @local_tun, $tun;
	    }
	}
    }

    return \@local_tun;
}

sub sessions {
    my ($self) = @_;
    
    my $cli = Funknet::Config::CLI->new( local_host => $self->{_local_host},
					 local_router => $self->{_local_router} 
				       );
    $cli->get_bgp;
    
    my $bgp = Funknet::Config::BGP->new( local_as => $self->{_local_as},
					 local_router => $self->{_local_router},
                                         routes  => $cli->networks,
					 source => 'host');

    for my $neighbor ($cli->neighbors) {
	$bgp->add_session(
	    description => $neighbor->description,
	    remote_as => $neighbor->remote_as,
	    local_addr => $cli->router_id, # not going to work quite right
	    remote_addr => $cli->peer_addr,
	);
    }
    return $bgp;
}

1;
