package Funknet::Config::CLI::Secrets;
use strict;
use vars qw/ $username $password $enable /;

=head1 NAME

Funknet::Config::CLI::Secrets

=head1 SYNOPSIS

my $username = Funknet::Config::CLI::Secrets->username($host);
etc.

=head1 DESCRIPTION

This module is an interface to whatever sort of
authentication-material store we decide to use.

=head1 LIMITATIONS/BUGS

This module is just a placeholder for something more reasonable. We
need to hang on to usernames, passwords and enable passwords for
IOS/Zebra. 

Two issues: this is a site-local thing; we don't want a central
database of usernames and passwords. Secondly, the code will often
want to access a router on '127.0.0.1'.

=cut

$username = { 
    '213.210.34.174' => '',
    '127.0.0.1'      => '',
};
$password = { 
    '213.210.34.174' => 'funknet',
    '127.0.0.1'      => 'zebra',
};
$enable   = { 
    '213.210.34.174' => 'funken',
    '127.0.0.1'      => '',
};

sub username {
    my ($class, $host) = @_;
    return $username->{$host};
}
sub password {
    my ($class, $host) = @_;
    return $password->{$host};
}
sub enable {
    my ($class, $host) = @_;
    return $enable->{$host};
}


1;
