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
					 local_os => 'ios',
					 local_router => 'ios',
					 local_host => '213.210.34.174',
				       );
my $whois_tun = $whois->tunnels;
my $whois_bgp = $whois->sessions;

for my $tun (@{$whois_tun}) {
    print $tun->config;
    print "\n";
}
print $whois_bgp->config;

my $host = Funknet::Config::Host->new( local_as => $ARGV[0],
				       local_os => 'ios',
				       local_router => 'ios',
				       local_host => '213.210.34.174',
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

my @diff_cmds = $whois_bgp->diff($host_bgp);
print join "\n", @diff_cmds;
print "\n";
