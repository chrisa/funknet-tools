package Funknet::Config::Whois;
use strict;
use Net::Whois::RIPE;
use Funknet::Config::Tunnel;
use Funknet::Config::TunnelSet;
use Funknet::Config::BGP;

=head1 NAME

Funknet::Config::Whois

=head1 SYNOPSIS

my $whois = Funknet::Config::Whois->new( local_as => 'AS65002',
					 local_os => 'ios',
					 local_router => 'ios',
					 local_host => '10.1.45.1',
				       );
my $whois_tun = $whois->tunnels;
my $whois_bgp = $whois->sessions;

=head1 DESCRIPTION

This module contains methods to retrieve configurations from the
objects in the whois database, and create a representation of it using
Funknet::Config objects. The module needs to know what operating
system it is supposed to work with - both in terms of the networking
(local_os) and routing software (local_router). It also needs to know
which Autonomous System the host is in, and an address where the
router interface may be found.

These parameters are passed to the constructor. Valid values for
local_os are 'bsd', 'solaris', 'linux' and 'ios'. Valid values for
local_router are 'ios' and 'zebra'.

The parameter local_as expects and 'AS' prefix on the
string. local_host expects an IPv4 address as a dotted-decimal string
(though a hostname may also work, this is asking for trouble).

=head1 METHODS

=head2 sessions

This method retrieves the BGP configuration for the router using the
objects in the whois database. A session is set up for every tunnel,
using the tunnel addresses themselves rather than the endpoint
addresses. 'network' statements are inferred from the route objects in
the local AS by an inverse lookup on the whois database.

The data structure is returned as a hashref. The top level data
structure is Funknet::Config::BGP, which contains the routes
advertised (network statements) for this BGP router. (todo: add other
BGP configuration statements to this object - ebgp multihop etc.)

The BGP object contains a list of Neighbor objects, which represent
the currently configured sessions. 

=head2 tunnels

This method retrieves the tunnel configuration for the router, based
on the tun: attributes of the relevant aut-num object. 

The data structure returned is a reference to an array of
Funknet::Config::Tunnel::$os objects where $os is as indicated by the
local_os flag passed to the constructor.

=cut

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
    return Funknet::Config::TunnelSet->new( tunnels => \@local_tun,
					    source => 'whois' );
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
