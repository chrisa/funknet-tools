package Funknet::Config::CommandSet;
use strict;

sub new {
    my ($class, %args) = @_;
    my $self = {};

    $self->{_cmds} = $args{cmds};
    if (defined $args{target} && $args{target} eq 'cli') {
	$self->{_local_router} = $args{local_router};
	$self->{_local_host} = $args{local_host};
	$self->{_local_os} = $args{local_os};
	bless $self, 'Funknet::Config::CommandSet::CLI';
	return $self;
    }
    if (defined $args{target} && $args{target} eq 'host') {
	$self->{_local_router} = $args{local_router};
	$self->{_local_host} = $args{local_host};
	$self->{_local_os} = $args{local_os};
	bless $self, 'Funknet::Config::CommandSet::Host';
 	return $self;
    }
    return undef;
}

sub cmds {
    my ($self) = @_;
    return @{ $self->{_cmds} };
}

package Funknet::Config::CommandSet::CLI;
use base qw/ Funknet::Config::CommandSet /;

sub as_text {
    my ($self) = @_;
    if (scalar @{ $self->{_cmds} }) {
	my $text = "in enable mode on $self->{_local_host}\n";
	$text .= join "\n", @{ $self->{_cmds} };
	return $text;
    } else {
	return '';
    }
}

sub apply {
    my ($self) = @_;

    # hand off to CLI module to get these commands executed in enable mode
   
    my $cli = Funknet::Config::CLI->new( local_host => $self->{_local_host},
					 local_router => $self->{_local_router} 
				       );
    
    my $rv = $cli->exec_enable( $self );
    return $rv;
}

package Funknet::Config::CommandSet::Host;
use base qw/ Funknet::Config::CommandSet /;

sub as_text {
    my ($self) = @_;
    if (scalar @{ $self->{_cmds} }) {
	my $text = "as root on localhost:\n";
	$text .= join "\n", @{ $self->{_cmds} };
	return $text;
    } else {
	return '';
    }
}

sub apply {
    my ($self) = @_;

    warn "in apply";
}

1;
