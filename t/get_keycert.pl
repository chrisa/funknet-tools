#!/usr/bin/perl
use strict;
use Funknet::KeyStash::Client;

my $param = $ARGV[0];

my $ks = Funknet::KeyStash::Client->new(
					www_user     => 'foo',
					www_pass     => 'bar',
					www_host     => 'blank.netdotnet.net',
					www_cert     => "/C=GB/O=Lemon Test/CN=blank.netdotnet.net",
					www_ca       => "/C=GB/O=Lemon Test/CN=blank.netdotnet.net",
					whois_host   => 'localhost',
					whois_port   => 4343,
					whois_source => 'FUNKNET',
					path         => '/tmp/ks',
				       );

unless (defined $ks) {
    warn "Couldn't get a KeyStash::Client";
    exit 1;
}

my $cert = $ks->get_cert($param);
if (!defined $cert) {
    warn "certificate not found: $param";
    exit 1;
}

my $cn = $cert->owner;
if (!defined $cn) {
    warn "using cert filename for key filename: $param";
    $cn = $param;
}

my $key = $ks->get_key($cn);
if (!defined $key) {
    warn "key not found: $cn";
    exit 1;
}

print "OK\n";
