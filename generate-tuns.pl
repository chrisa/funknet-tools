#!/usr/local/bin/perl -w
use strict;
use lib './lib';
use Data::Dumper;
use Funknet::Config::Whois;

unless (scalar @ARGV == 1) {
    print STDERR "usage: $0 local_as\n";
    exit(1);
}

my $local_as = $ARGV[0];

my $whois = Funknet::Config::Whois->new();
my $local_tun = $whois->tunnels($local_as);
my $local_bgp = $whois->sessions($local_as);

for my $tun (@{$local_tun}) {
    print $tun->as_string;
    print "\n";
}

print $local_bgp->config;
