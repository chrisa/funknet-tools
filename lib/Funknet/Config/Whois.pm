package Funknet::Config::Whois;
use strict;
use Net::Whois::RIPE;
use Funknet::Config::Tunnel;
use Funknet::Config::BGP;

sub new {
    my ($class) = @_;
    my $self = bless {}, $class;
    $self->{_net_whois_ripe} = Net::Whois::RIPE->new( 'whois.funknet.org' );
    $self->{_net_whois_ripe}->source('FUNKNET');
    return $self;
}

sub tunnels {
    my ($self, $local_as) = @_;
    my $w = $self->{_net_whois_ripe};
    $w->type('aut-num');
    my $as = $w->query($local_as);
    
    my @local_tun;
    
    foreach my $tun_name ($as->tun) {
	
	$w->type('tunnel');
	my $tun = $w->query($tun_name);
	
	for my $i ( 0..1 ) {
	    my @as = $tun->as;
	    my @ep = $tun->endpoint;
	    my @ad = $tun->address;
	    
	    if ($as[$i] eq $local_as) {
		push @local_tun, 
		Funknet::Config::Tunnel->new(
		    name => $tun_name,
		    local_address => $ad[$i],
		    remote_address => $ad[1-$i],
		    local_endpoint => $ep[$i],
		    remote_endpoint => $ep[1-$i],
		    type => $tun->type,
		    source => 'whois',
		);
	    }
	}
    }
    return \@local_tun;
}

sub sessions {
    my ($self, $local_as) = @_;
    my $w = $self->{_net_whois_ripe};

    $w->type('route');
    $w->inverse_lookup('origin');
    my $routes = $w->query_iterator($local_as);
    my @routes;
    while (my $obj = $routes->next) {
        push @routes, $obj->route;
    }

    $w->type('aut-num');
    $w->{FLAG_i} = '';
    my $as = $w->query($local_as);


    my $bgp = Funknet::Config::BGP->new( local_as => $local_as,
                                         routes  => \@routes,
					 source => 'whois');
    
    for my $tun_name ($as->tun) {
	
	$w->type('tunnel');
	my $tun = $w->query($tun_name);
	
	for my $i ( 0..1 ) {
	    my @as = $tun->as;
	    my @ad = $tun->address;
	    
	    if ($as[$i] eq $local_as) {
		$bgp->add_session(
		    description => $tun_name,
		    remote_as => $as[1-$i],
		    local_addr => $ad[$i],
		    remote_addr => $ad[1-$i],
		);
	    }
	}
    }
    return $bgp;
}
    

1;
