#!/usr/local/bin/perl -w
use strict;
use lib './lib';
use Data::Dumper;
use Funknet::Config;

unless (scalar @ARGV == 4) {
    print STDERR "usage: $0 local_as local_router local_os local_host\n";
    exit(1);
}

my $whois = Funknet::Config::Whois->new( local_as => $ARGV[0],
					 local_router => $ARGV[1],
					 local_os => $ARGV[2],
					 local_host => $ARGV[3],
				       );

my $host = Funknet::Config::Host->new( local_as => $ARGV[0],
				       local_router => $ARGV[1],
				       local_os => $ARGV[2],
				       local_host => $ARGV[3],
				     );
my $whois_tun = $whois->tunnels;
my $whois_bgp = $whois->sessions;
my $host_tun = $host->tunnels;
my $host_bgp = $host->sessions;

print Dumper $whois_bgp;
print Dumper $host_bgp;
print Dumper $whois_tun;
print Dumper $host_tun;

print "================================================\n";

my @bgp_cmds = $whois_bgp->diff($host_bgp);
print join "\n", @bgp_cmds;
print "\n";

my @tun_cmds = $whois_tun->diff($host_tun);
print join "\n", @tun_cmds;
print "\n";

