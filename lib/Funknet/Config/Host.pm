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
	@local_tun = $cli->get_interfaces;
	
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
    
    my $cli = Funknet::Config::CLI->new( local_as => $self->{_local_as},
					 local_host => $self->{_local_host},
					 local_router => $self->{_local_router} 
				       );
    my $bgp = $cli->get_bgp;
}

1;
