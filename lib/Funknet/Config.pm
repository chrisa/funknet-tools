package Funknet::Config;
use strict;
use Funknet::Config::Whois;
use Funknet::Config::Host;
use Funknet::Config::CommandSet;
use Funknet::Config::ConfigFile;

=head1 NAME

Funknet::Config

=head1 SYNOPSIS

    my $conf = new Funknet::Config( configfile => '/full/path/to/configfile' );

=head1 DESCRIPTION

=head1 METHODS

=head2 new
=head2 diff
=head2 apply

=cut

sub new {
    my ($class,%args) = @_;
    my $self = bless {}, $class;
    $self->{_error} = [];
    $self->{_warn} = [];
    $self->{_config} = Funknet::Config::ConfigFile->new( $args{configfile} )
	or die "couldn't load config file";
    return $self;
}

sub error {
    my ($self, $errstr) = @_;
    if (defined $errstr) {
	push @{ $self->{_error} }, $errstr;
	return 1;
    } else {
	if (scalar @{ $self->{_error} }) {
	    return wantarray?@{ $self->{_error} }:join "\n", @{ $self->{_error} };
	} else {
	    return undef;
	}
    }
}

sub warn {
    my ($self, $errstr) = @_;
    if (defined $errstr) {
	push @{ $self->{_warn} }, $errstr;
	if ($self->{_config}->{warnings}) {
	    print STDERR "$errstr\n";
	}
	return 1;
    } else {
	if (scalar @{ $self->{_warn} }) {
	    return wantarray?@{ $self->{_warn} }:join "\n", @{ $self->{_warn} };
	} else {
	    return undef;
	}
    }
}

sub bgp_diff {
    my ($self) = @_;
    
    my $whois = Funknet::Config::Whois->new();
    my $host = Funknet::Config::Host->new();
    my $whois_bgp = $whois->sessions;
    my $host_bgp = $host->sessions;
    
    my $diff = Funknet::Config::CommandSet->new( cmds => [ $whois_bgp->diff($host_bgp) ],
					         target => 'cli',
					       );
    return $diff;
}

sub tun_diff {
    my ($self) = @_;
    my $l = Funknet::Config::ConfigFile->local;
    
    my $whois = Funknet::Config::Whois->new();
    my $host = Funknet::Config::Host->new();
    my $whois_tun = $whois->tunnels;
    my $host_tun = $host->tunnels;
    
    my $diff;
    if ($l->{os} eq 'ios') {
	$diff = Funknet::Config::CommandSet->new( cmds => [ $whois_tun->diff($host_tun) ],
						  target => 'cli',
						);
    } else {
	$diff = Funknet::Config::CommandSet->new( cmds => [ $whois_tun->diff($host_tun) ],
						  target => 'host',
						);
    }
    return $diff;
}

1;
