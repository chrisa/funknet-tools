package Funknet::Config::TunnelSet;
use strict;
use base qw/ Funknet::Config /;

=head1 NAME

Funknet::Config::TunnelSet

=head1 DESCRIPTION

Provides a collection object for Tunnels. Contains the ->diff method
for tunnels. 

=head1 METHODS

=head2 new(source => 'whois', tunnels => \@tuns)

Takes the source and a listref of Tunnels. 

=head2 diff($hostobj)

Called on a TunnelSet object of source whois and passed a TunnelSet
object of source host, returns the commands required to update the
host's tunnel config to that specified in the whois.

=head1 TODO

It should probably be possible to add Tunnels via a method, rather
than all at once by passing the constructor a listref.

The diff method should take note of the ignorelist for interfaces.

=cut

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
	$whois->warn("diff passed objects backwards");
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
    my @ignore_if = Funknet::Config::ConfigFile->ignore_if;
    my $local_os_type = Funknet::Config::ConfigFile->local_os;

    for my $w ($whois->tunnels) {
	unless ($host_tuns->{$w->as_hashkey}) {

	    my $tun_type = $w->type;
	    if($local_os_type eq 'bsd' && $tun_type eq 'ipip') 
	    {
		$tun_type = 'gif';
	    }
	    while((scalar(grep /$tun_type$next_inter/,@ignore_if))>0 )
	    {
		$next_inter++;
	    }
	    push @cmds, $w->create($next_inter);
	    $next_inter++;
	}
    }
    return @cmds;
}

1;
