package Funknet::Config::Whois;
use strict;
use Net::Whois::RIPE;
use Funknet::Config::Tunnel;
use Funknet::Config::BGP;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    $self->{_net_whois_ripe} = Net::Whois::RIPE->new( 'whois.funknet.org' );
    $self->{_net_whois_ripe}->source('FUNKNET');

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
    my $w = $self->{_net_whois_ripe};
    $w->type('aut-num');
    my $as = $w->query($self->{_local_as});
    
    my @local_tun;
    
    foreach my $tun_name ($as->tun) {
	
	$w->type('tunnel');
	my $tun = $w->query($tun_name);
	
	for my $i ( 0..1 ) {
	    my @as = $tun->as;
	    my @ep = $tun->endpoint;
	    my @ad = $tun->address;
	    
	    if ($as[$i] eq $self->{_local_as}) {
		push @local_tun, 
		Funknet::Config::Tunnel->new(
		    name => $tun_name,
		    local_address => $ad[$i],
		    remote_address => $ad[1-$i],
		    local_endpoint => $ep[$i],
		    remote_endpoint => $ep[1-$i],
		    type => $tun->type,
		    local_os => $self->{_local_os},
		    source => 'whois',
		);
	    }
	}
    }
    return \@local_tun;
}

sub sessions {
    my ($self) = @_;
    my $w = $self->{_net_whois_ripe};

    $w->type('route');
    $w->inverse_lookup('origin');
    my $routes = $w->query_iterator($self->{_local_as});
    my @routes;
    while (my $obj = $routes->next) {
        if (my $route = $obj->route) {
            push @routes, $route;
        }
    }

    $w->type('aut-num');
    $w->{FLAG_i} = '';
    my $as = $w->query($self->{_local_as});


    my $bgp = Funknet::Config::BGP->new( local_as => $self->{_local_as},
					 local_router => $self->{_local_router},
                                         routes  => \@routes,
					 source => 'whois');
    
    for my $tun_name ($as->tun) {
	
	$w->type('tunnel');
	my $tun = $w->query($tun_name);
	
	for my $i ( 0..1 ) {
	    my @as = $tun->as;
	    my @ad = $tun->address;
	    
	    if ($as[$i] eq $self->{_local_as}) {
		
		my $acl_in = Funknet::Config::AccessList->new( source_as   => $as[$i],
							       peer_as     => $as[1-$i],
							       source_addr => $ad[$i],
							       peer_addr   => $ad[1-$i],
							       dir         => 'import',
							       source      => 'whois',
							     );
		
		my $acl_out = Funknet::Config::AccessList->new( source_as   => $as[$i],
								peer_as     => $as[1-$i],
								source_addr => $ad[$i],
								peer_addr   => $ad[1-$i],
								dir         => 'export',
								source      => 'whois',
							      );
		
		$bgp->add_session(
		    description => $tun_name,
		    remote_as => $as[1-$i],
		    local_addr => $ad[$i],
		    remote_addr => $ad[1-$i],
		    acl_in => $acl_in, 
		    acl_out => $acl_out,
		);
	    }
	}
    }
    return $bgp;
}
    

1;
