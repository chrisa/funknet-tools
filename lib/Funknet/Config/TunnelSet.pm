package Funknet::Config::TunnelSet;
use strict;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    $self->{_tunnels} = $args{tunnels};
    $self->{_source} = $args{source};
    
    return $self;
}

sub tunnels {
    my ($self) = @_;
    return @{$self->{_tunnels}};
}

sub config {
    my ($self) = @_;
    
    for my $tun (@{$self->{_tunnels}}) {
	print $tun->config;
	print "\n";
    }
}

sub source {
    my ($self) = @_;
    return $self->{_source};
}

sub diff {
    my ($whois, $host) = @_;
    my (@cmds, $next_inter);
    $next_inter = 0;

    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
	warn "diff passed objects backwards";
	return undef;
    }    
    
    # create hashes

    my ($whois_tuns, $host_tuns);
    for my $tun ($whois->tunnels) {
	$whois_tuns->{$tun->as_hashkey} = 1;
    }
    for my $tun ($host->tunnels) {
	$host_tuns->{$tun->as_hashkey} = 1;
	# keep track of interface numbering
	if ($tun->interface > $next_inter) {
	    $next_inter = $tun->interface;
	}
    }

    for my $h ($host->tunnels) {
	unless ($whois_tuns->{$h->as_hashkey}) {
	    push @cmds, $h->delete;
	}
    }
    for my $w ($whois->tunnels) {
	unless ($host_tuns->{$w->as_hashkey}) {
	    push @cmds, $w->create($next_inter);
	    $next_inter++;
	}
    }
    return @cmds;
}

1;
