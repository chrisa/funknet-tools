\#!/usr/local/bin/perl -w
use strict;
use lib './lib';
use Funknet::Config;

unless (scalar @ARGV == 4) {
    print STDERR "usage: $0 local_as local_router local_os local_host\n";
    exit(1);
}

# Create a Config object, giving it the details of our 
# local system.
my $config = Funknet::Config->new( local_as => $ARGV[0],
				   local_router => $ARGV[1],
				   local_os => $ARGV[2],
				   local_host => $ARGV[3],
				 );

# Generate the changes between current (host) and desired (whois) config.
my $bgp = $config->bgp_diff or die "bgp_diff failed: ".$config->error;
my $tun = $config->tun_diff or die "tun_diff failed: ".$config->error;

# Dump the commands generated by the diff.
print "Proposed changes:\n";
print "BGP:\n";
print $bgp->as_text;
print "\n";
print "Tunnels:\n";
print $tun->as_text;
print "\n";

# Run the commands on the local system.
$bgp->apply;
$tun->apply;
