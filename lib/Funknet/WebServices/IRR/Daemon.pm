# "Programming Web Services with Perl", by Randy J. Ray and Pavel Kulchenko
# O'Reilly and Associates, ISBN 0-596-00206-8.
#
# The sample daemon class derived by sub-classing the
# SOAP::Transport::HTTP::Daemon class, which is in turn
# derived from HTTP::Daemon.
#
package Funknet::WebServices::IRR::Daemon;

use strict;
use vars qw(@ISA);
use Data::Dumper;
use SOAP::Transport::HTTP;
@ISA = qw(SOAP::Transport::HTTP::Daemon);

use Funknet::WebServices::IRR;

1;


sub request {

    my $self = shift;
    if (my $request = $_[0]) {
        my @cookies = $request->headers->header('cookie');
        %Funknet::WebServices::IRR::SOAP::COOKIES = ();
        for my $line (@cookies) {
            for (split(/; /, $line)) {
                next unless /(.*?)=(.*)/;
                $Funknet::WebServices::IRR::SOAP::COOKIES{$1} = $2;
            }
        }
    }
    $self->SUPER::request(@_);
}
