#!/usr/bin/perl -w
use strict;
use Data::Dumper;
use Funknet::Config;
use Funknet::Config::CLI;

my $config = Funknet::Config->new( configfile  => $ARGV[0] );

my $cli = Funknet::Config::CLI->new();
my $bgp = $cli->get_bgp;

print Dumper $bgp;
