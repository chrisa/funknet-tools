#!/usr/local/bin/perl -w
use strict;
use lib './lib';
use Data::Dumper;
use Funknet::Config::Whois;
use Funknet::Config::Host;

unless (scalar @ARGV == 4) {
    print STDERR "usage: $0 local_as local_router local_os local_host\n";
    exit(1);
}

my $local_as = $ARGV[0];

my $whois = Funknet::Config::Whois->new( local_as => $ARGV[0],
					 local_os => $ARGV[2],
					 local_router => $ARGV[1],
					 local_host => $ARGV[3],
				       );
my $whois_tun = $whois->tunnels;
my $whois_bgp = $whois->sessions;

for my $tun (@{$whois_tun}) {
    print $tun->config;
    print "\n";
}
print $whois_bgp->config;

my $host = Funknet::Config::Host->new( local_as => $ARGV[0],
				       local_os => $ARGV[2],
				       local_router => $ARGV[1],
				       local_host => $ARGV[3],
				     );
my $host_tun = $host->tunnels;
my $host_bgp = $host->sessions;

for my $tun (@{$host_tun}) {
    print $tun->config;
    print "\n";
}
print $host_bgp->config;
print Dumper $whois_bgp;
print Dumper $host_bgp;

print "================================================\n";

my @diff_cmds = $whois_bgp->diff($host_bgp);
print join "\n", @diff_cmds;
print "\n";
