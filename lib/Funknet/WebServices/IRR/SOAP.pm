package Funknet::WebServices::IRR::SOAP;
use strict;

# this is the SOAP glue between IRR::Apache.pm and IRR.pm

use vars qw(@ISA %COOKIES);

use SOAP::Lite;
use Funknet::WebServices::IRR;

@ISA = qw(Funknet::WebServices::IRR);

BEGIN {
    no strict 'refs';

    for my $method qw( RtConfig ) {
        eval "sub $method";
        *$method = sub {
            my $self = shift->new;
            die SOAP::Fault
                    ->faultcode('Server.RequestError')
                    ->faultstring('Could not get object')
                unless $self;

            my $smethod = "SUPER::$method";
            my $res = $self->$smethod(@_);
            die SOAP::Fault
                    ->faultcode('Server.ExecError')
                    ->faultstring("Execution error: $res")
                unless ref($res);

            $res;
        };
    }
}

1;


# The class constructor. It is designed to be called by each
# invocation of each other method. As such, it returns the
# first argument immediately if it is already an object of
# the class. This lets users of the class rely on constructs
# such as cookie-based authentication, where each request
# calls for a new object instance.
#
sub new {
    my $class = shift;
    return $class if ref($class);

    my $self;
    # If there are no arguments, but available cookies, then
    # that is the signal to work the cookies into play
    if ((! @_) and (keys %COOKIES)) {
        # Start by getting the basic, bare object
        $self = $class->SUPER::new();
        # Then call SetUser. It will die with a SOAP::Fault
        # on any error
        $self->SetUser;
    } else {
        $self = $class->SUPER::new(@_);
    }

    $self;
}

#
# This derived version of SetUser hands off to the parent-
# class version if any arguments are passed. If none are,
# it looks for cookies to provide the authentication. The
# user name is extracted from the cookie, and the "user"
# and "cookie" arguments are passed to the parent-class
# SetUser method with these values.
#
sub SetUser {
    my $self = shift->new;
    my %args = @_;

    return $self->SUPER::SetUser(%args) if (%args);

    my $user;
    my $cookie = $COOKIES{user};
    return $self unless $cookie;
    ($user = $cookie) =~ s/%([0-9a-f]{2})/chr(hex($1))/ge;
    $user =~ s/%([0-9a-f]{2})/chr(hex($1))/ge;
    $user =~ s/::.*//;

    my $res = $self->SUPER::SetUser(user   => $user,
                                    cookie => $cookie);
    die SOAP::Fault
            ->faultcode('Server.AuthError')
            ->faultstring("Authorization failed: $res")
        unless ref($res);

    $self;
}
