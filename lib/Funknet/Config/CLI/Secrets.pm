package Funknet::Config::CLI::Secrets;
use strict;
use vars qw/ $username $password $enable /;

# this is pretty much a placeholder for a decent
# way of holding on to usernames/passwords

$username = { '213.210.34.174' => '' };
$password = { '213.210.34.174' => 'funknet' };
$enable   = { '213.210.34.174' => '' };

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
