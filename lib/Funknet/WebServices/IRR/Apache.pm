package Funknet::WebServices::IRR::Apache;
use strict;
use vars qw(@ISA);
use SOAP::Transport::HTTP;
use Funknet::WebServices::IRR::SOAP;
@ISA = qw(SOAP::Transport::HTTP::Apache);

1;

# This is the Apache-SOAP glue code. 

sub handler ($$) {
    
    print STDERR "in IRR::Apache handler\n";

    my ($self, $request) = @_;

    my $cookies = $request->header_in('cookie');
    my @cookies = ref $cookies ? @$cookies : $cookies;
    %Funknet::WebServices::IRR::SOAP::COOKIES = ();
    for my $line (@cookies) {
        for (split(/; /, $line)) {
            next unless /(.*?)=(.*)/;
            $Funknet::WebServices::IRR::SOAP::COOKIES{$1} = $2;
        }
    }
    $self->SUPER::handler($request);
}
