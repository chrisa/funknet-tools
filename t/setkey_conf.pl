#!/usr/bin/perl
use strict;
use Data::Dumper;
use Funknet::Config::Encryption::IPSec::KAME;

undef $/;
my $conf = <STDIN>;
my $data = Funknet::Config::Encryption::IPSec::KAME::_parse_setkey_conf($conf);
print Dumper $data;

