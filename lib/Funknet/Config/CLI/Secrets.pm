package Funknet::Config::CLI::Secrets;
use strict;
use vars qw/ $username $password $enable /;

# this is pretty much a placeholder for a decent
# way of holding on to usernames/passwords

$username = { 
    '213.210.34.174' => '',
    '127.0.0.1'      => '',
};
$password = { 
    '213.210.34.174' => 'funknet',
    '127.0.0.1'      => 'zebra',
};
$enable   = { 
    '213.210.34.174' => '',
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
