#!/usr/bin/perl
use strict;
use Data::Dumper;
use Funknet::Config::Encryption::IPSec::KAME;

$::RD_TRACE = 1;

undef $/;
my $conf = <STDIN>;
my $data = Funknet::Config::Encryption::IPSec::KAME::_parse_racoon_conf($conf);
print Dumper $data;

