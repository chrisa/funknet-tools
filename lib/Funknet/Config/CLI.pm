package Funknet::Config::CLI;
use strict;
use Funknet::Config::CLI::Secrets;
use Net::Telnet;

my $prompts = { 
    zebra => '/[\>\#]$/',
    ios   => '/[\>\#] $/',
};
my $if_ports = {
    zebra => 2601,
    cisco => 23,
};
my $bgp_ports = {
    zebra => 2605,
    cisco => 23,
};

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    if (defined $args{local_router}) {
	$self->{_local_router} = $args{local_router};
    } else {
	return undef;
    }
    if (defined $args{local_host}) {
	$self->{_local_host} = $args{local_host};
    } else {
	return undef;
    }

    $self->{_username} = Funknet::Config::CLI::Secret->username( $self->{_local_host} );
    $self->{_password} = Funknet::Config::CLI::Secret->password( $self->{_local_host} );
    $self->{_enable}   = Funknet::Config::CLI::Secret->enable(   $self->{_local_host} );

    $self->check_login
	or return undef;
    
    return $self;
}

sub check_login {
    my ($self) = @_;
    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => $prompts->{$self->{_local_router}},
			      Port    => $if_ports->{$self->{_local_router}},
			    );
    $t->open($self->{_local_host});
    $t->cmd($self->{_password});
    $t->getline;
    $t->cmd('enable');
    $t->cmd($self->{_enable});
    my $p = $t->getline;
    if ($p =~ /#/) {
	return 1;
    } else {
	return undef;
    }
}



1;
