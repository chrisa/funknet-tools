#!/usr/bin/perl -w
# "Programming Web Services with Perl", by Randy J. Ray and Pavel Kulchenko
# O'Reilly and Associates, ISBN 0-596-00206-8.

#
# Version 2 of the daemon, this time using a SOAP layer for
# the methods to expose, and a daemon class that derives
# from the original HTTP::Daemon-based class for the server
# layer. Combined, these allow for basic authentication of
# user operations.
#
use strict;
use lib '/home/funknet/funknet-tools/lib';

# Again, loading this now saves effort for SOAP::Lite
use Funknet::WebServices::IRR;
use Funknet::WebServices::IRR::SOAP;
use Funknet::WebServices::IRR::Daemon;

my $port = pop(@ARGV) || 9000;
my $host = shift(@ARGV) || 'localhost';

Funknet::WebServices::IRR::Daemon
    ->new(LocalAddr => $host, LocalPort => $port,
          Reuse => 1)
    ->dispatch_to('/home/funknet/funknet-tools/lib/Funknet/WebServices', 
		  'Funknet::WebServices::IRR')
    ->handle;

exit 0;
