#!/usr/local/bin/perl -w
use strict;
use lib './lib';
use Data::Dumper;
use Funknet::Config::Whois;

unless (scalar @ARGV == 3) {
    print STDERR "usage: $0 local_as local_os doit";
    exit(1);
}

my $local_as = $ARGV[0];
my $local_os = $ARGV[1];
my $doit = $ARGV[2];

my $whois = Funknet::Config::Whois->new();
my $local_tun = $whois->tunnels($local_as);
my $local_bgp = $whois->sessions($local_as);

for my $tun (@{$local_tun}) {
    print $tun->as_string;
    print "\n";
}

print Dumper $local_bgp;
print $local_bgp->config;

sub tunnelup_bsd {
    my ($tun) = @_;

    my ($destroy, $create, $endpoints, $addresses);

    if ($tun->{type} eq 'ipip') {
	
	$destroy = "ifconfig gif$tun->{index} destroy";
	$create = "ifconfig gif$tun->{index} create";
	$endpoints = "ifconfig gif$tun->{index} tunnel $tun->{local_endpoint} $tun->{remote_endpoint} mtu 1480";
	$addresses = "ifconfig gif$tun->{index} inet $tun->{local_address} $tun->{remote_address} netmask 255.255.255.252";
    }
    
    if ($doit) {
    } else {
	print $destroy, "\n", $create, "\n", $endpoints, "\n", $addresses, "\n";
    }
}

