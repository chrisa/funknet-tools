package Funknet::Config;
use strict;
use Funknet::Config::Whois;
use Funknet::Config::Host;
use Funknet::Config::CommandSet;
use Funknet::Config::Validate qw/ is_valid_as is_valid_os 
                                  is_valid_router is_ipv4 /;

=head1 NAME

Funknet::Config

=head1 SYNOPSIS

    my $conf = new Funknet::Config( local_as => 'AS65000',
                                    local_router => 'zebra',
			       	    local_os => 'bsd',
				    local_host => '127.0.0.1' 
    );

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
    
    unless (defined $args{local_as} && is_valid_as($args{local_as})) {
	$self->error("local_as missing or invalid");
      }
    unless (defined $args{local_os} && is_valid_os($args{local_os})) {
	$self->error("local_os missing or invalid");
      }
    unless (defined $args{local_router} && is_valid_router($args{local_router})) {
	$self->error("local_router missing or invalid");
      }
    unless (defined $args{local_host} && is_ipv4($args{local_host})) {
	$self->error("local_host missing or invalid");
      }

    if ($self->error) {
	warn $self->error;
	return undef;
    }

    $self->{_local_as} = $args{local_as};
    $self->{_local_os} = $args{local_os};
    $self->{_local_router} = $args{local_router};
    $self->{_local_host} = $args{local_host};
    
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
    
    my $whois = Funknet::Config::Whois->new( local_as => $self->{_local_as},
					     local_router => $self->{_local_router},
					     local_os => $self->{_local_os},
					     local_host => $self->{_local_host},
					   );

    my $host = Funknet::Config::Host->new( local_as => $self->{_local_as},
					   local_router => $self->{_local_router},
					   local_os => $self->{_local_os},
					   local_host => $self->{_local_host},
					 );

    my $whois_bgp = $whois->sessions;
    my $host_bgp = $host->sessions;
    
    my $diff = Funknet::Config::CommandSet->new( cmds => [ $whois_bgp->diff($host_bgp) ],
					         target => 'cli',
						 local_router => $self->{_local_router},
						 local_host => $self->{_local_host},
					       );
    return $diff;
}

sub tun_diff {
    my ($self) = @_;
    
    my $whois = Funknet::Config::Whois->new( local_as => $self->{_local_as},
					     local_router => $self->{_local_router},
					     local_os => $self->{_local_os},
					     local_host => $self->{_local_host},
					   );
    
    my $host = Funknet::Config::Host->new( local_as => $self->{_local_as},
					   local_router => $self->{_local_router},
					   local_os => $self->{_local_os},
					   local_host => $self->{_local_host},
					 );
    my $whois_tun = $whois->tunnels;
    my $host_tun = $host->tunnels;
    
    my $diff;
    if ($self->{_local_os} eq 'ios') {
	$diff = Funknet::Config::CommandSet->new( cmds => [ $whois_tun->diff($host_tun) ],
						  target => 'cli',
						  local_host => $self->{_local_host},
						  local_os => $self->{_local_os},
						  local_router => $self->{_local_router},
						);
    } else {
	$diff = Funknet::Config::CommandSet->new( cmds => [ $whois_tun->diff($host_tun) ],
						  target => 'host',
						  local_host => $self->{_local_host},
						  local_router => $self->{_local_router},
						  local_os => $self->{_local_os},
						);
    }
    return $diff;
}

1;
