#!/usr/bin/perl -w

use strict;

use lib './lib';

use Funknet::Whois;
use Net::Whois::RIPE;
use Nagios::Config;
use Data::Dumper;

my @ass;
my @as_names;
my @done;
my %nerd_autnum_objects;
my %splurby_nerd_tunnels;
my %as_names;
my %as_nums;
my %endpoints;
my %nerd_tunnels;

my $whois = Net::Whois::RIPE->new( 'whois.funknet.org');
unless (defined $whois)
{ 
        die "Error getting a Funknet::Config::Whois object\n";
}

my $transobj = $whois->query('AS-FUNKTRANSIT');

@ass = $transobj->members;

$whois->type('aut-num');

foreach my $thing ($transobj->members)
{
	next if (($thing eq 'AS65000') or ($thing eq 'AS65023'));
	$whois->type('aut-num');
	my $reply = $whois->query($thing);
	$nerd_autnum_objects{$thing} = $reply;
	$as_names{$thing} = $reply->as_name;
	$as_nums{$reply->as_name} = $thing;
}

$whois->type('aut-num');
my $splurby_aut_num = $whois->query('AS65000');

foreach my $thing ($splurby_aut_num->tun)
{
		$whois->type('tunnel');
		my $tun = $whois->query($thing);
		$splurby_nerd_tunnels{$thing} = $tun;		
}

foreach my $splurby_tun (keys(%splurby_nerd_tunnels))
{
	my @endpoints = $splurby_nerd_tunnels{$splurby_tun}->endpoint;
	my @address = $splurby_nerd_tunnels{$splurby_tun}->address;
	my @ass = $splurby_nerd_tunnels{$splurby_tun}->as;
	my $ip;
	my $ip_addy;
	my $other_as;
	my $as_name;
	my $as_num;
	my $splurby_as='AS65000';
        my ($as1,$as2) = @ass;
	if ($as1 =~ /AS65000/m)
	{ 
		my $tmp = shift(@endpoints);
		$ip = shift(@endpoints);
		my $tmp_addy = shift(@address);
		$ip_addy = shift(@address);
		$other_as = $as2;
	}
	elsif ($as2  =~ /AS65000/m)
	{
		$ip = shift(@endpoints);
		$ip_addy = shift(@address);
		$other_as = $as1;
	}
	$endpoints{$other_as} = $ip;
	$as_name=$as_names{$other_as};
	$as_num=$as_nums{$as_name};
	print qq[
define host{
        host_name               $as_name
        alias                   $as_num
        address                 $ip
        check_command           check_ping_remote
        checks_enabled          1
        max_check_attempts      5
        notification_interval           30
        notification_period             24x7
        notification_options            d,u,r
        }
define host{
        host_name               ${as_name}-funknet
        alias                   $as_num
        address                 $ip_addy
	parent_hosts		$as_name
        check_command           check_ping_remote
        checks_enabled          1
        max_check_attempts      5
        notification_interval           30
        notification_period             24x7
        notification_options            d,u,r
        }
];

}

