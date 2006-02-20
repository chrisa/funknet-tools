#!/usr/bin/perl
use strict;
use Data::Dumper;
use Test::More qw/ no_plan /;

BEGIN { use_ok ( 'Funknet::Whois::Date' ); }

my $parse_tests = [
                   [ '2003-02-15T13:50:05-05:00', 1045335005 ],
                   [ '1970-01-01T00:00:00-00:00', 0          ],
                   [ '1969-12-31T23:59:59-00:00', -1         ],
                  ];

my $fwd = Funknet::Whois::Date->new('W3CDTF');

for my $t (@$parse_tests) {
     my $time_t = $fwd->parse_datetime($t->[0]);
     is($time_t, $t->[1], "parse $t->[0] as $t->[1]");
}

my $format_tests = [
                    [ 1045335005, '2003-02-15T18:50:05-00:00' ],
                    [ 0,          '1970-01-01T00:00:00-00:00' ],
                    [ -1,         '1969-12-31T23:59:59-00:00' ],
                   ];

for my $t (@$format_tests) {
     my $string = $fwd->format_datetime($t->[0]);
     is($string, $t->[1], "format $t->[0] as $t->[1]");
}
