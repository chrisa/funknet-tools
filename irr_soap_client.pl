#!/usr/bin/perl -w
use strict;
use Data::Dumper;
use URI;
use SOAP::Lite;

my $soap = SOAP::Lite
    ->uri('http://www.funknet.org/Funknet/WebServices/IRR/SOAP')
    ->proxy('http://www.funknet.org/SOAP');

my $result = $soap->RtConfig( @ARGV );

if ($result->fault) {
    die "$0: Operation failed: " . $result->faultstring;
}
my $acl = $result->result;
print "$acl\n";
