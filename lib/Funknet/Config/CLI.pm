package Funknet::Config::CLI;
use strict;
use Funknet::Config::CLI::Secrets;
use Funknet::Config::CLI::Zebra;
use Funknet::Config::CLI::IOS;
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

    $self->{_username} = Funknet::Config::CLI::Secrets->username( $self->{_local_host} );
    $self->{_password} = Funknet::Config::CLI::Secrets->password( $self->{_local_host} );
    $self->{_enable}   = Funknet::Config::CLI::Secrets->enable(   $self->{_local_host} );

    $self->check_login
	or return undef;
    
    # rebless into relevant class

    $args{local_router} eq 'ios' and 
	bless $self, 'Funknet::Config::CLI::IOS';
    $args{local_router} eq 'zebra' and 
	bless $self, 'Funknet::Config::CLI::Zebra';

    return $self;
}

sub check_login {
    my ($self) = @_;

    return 1;
    
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
