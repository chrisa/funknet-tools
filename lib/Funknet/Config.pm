package Funknet::Config;
use strict;
use Funknet::Config::Whois;
use Funknet::Config::Host;
use Funknet::Config::CommandSet;
use Funknet::Config::ConfigFile;
use Funknet::Config::Validate qw/ is_valid_as is_valid_os 
                                  is_valid_router is_ipv4 /;

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

    $self->{_config} = Funknet::Config::ConfigFile->new( $args{configfile} )
	or die "couldn't load config file";
    
    unless (defined $self->{_config}->local_as && 
	    is_valid_as($self->{_config}->local_as)) {
	$self->error("local_as missing or invalid");
    }
    unless (defined $self->{_config}->local_os && 
	    is_valid_os($self->{_config}->local_os)) {
	$self->error("local_os missing or invalid");
    }
    unless (defined $self->{_config}->local_router && 
	    is_valid_router($self->{_config}->local_router)) {
	$self->error("local_router missing or invalid");
    }
    unless (defined $self->{_config}->local_host && 
	    is_ipv4($self->{_config}->local_host)) {
	$self->error("local_host missing or invalid");
    }
    
    if ($self->error) {
	warn $self->error;
	return undef;
    }

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
