#!/usr/local/bin/perl -w
use strict;
use lib './lib';
use Data::Dumper;
use Funknet::Config::Whois;
use Funknet::Config::Host;

unless (scalar @ARGV == 1) {
    print STDERR "usage: $0 local_as\n";
    exit(1);
}

my $local_as = $ARGV[0];

my $whois = Funknet::Config::Whois->new( local_as => $ARGV[0],
					 local_os => 'bsd',
					 local_router => 'zebra'
				       );
my $whois_tun = $whois->tunnels;
my $whois_bgp = $whois->sessions;

for my $tun (@{$whois_tun}) {
    print $tun->config;
    print "\n";
}
print $whois_bgp->config;

my $host = Funknet::Config::Host->new( local_as => $ARGV[0],
				       local_os => 'bsd',
				       local_router => 'zebra'
				     );
my $host_tun = $host->tunnels;
for my $tun (@{$host_tun}) {
    print $tun->config;
    print "\n";
}
