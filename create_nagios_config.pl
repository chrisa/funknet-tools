#!/usr/bin/perl -w

use strict;

use lib './lib';

use Funknet::Whois;
use Net::Whois::RIPE;
#use Nagios::Config; # no need for this yet
use Data::Dumper;

my @ass;
my @as_names;
my @done;
my %nerd_autnum_objects;
my %blank_nerd_tunnels;
my %as_names;
my %as_nums;
my %endpoints;
my %nerd_tunnels;
my $hosts;
my $services;
my $hosts_inside;
my $hosts_outside;

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
my $blank_aut_num = $whois->query('AS65023');

foreach my $thing ($blank_aut_num->tun)
{
		$whois->type('tunnel');
		my $tun = $whois->query($thing);
		$blank_nerd_tunnels{$thing} = $tun;		
}

foreach my $blank_tun (keys(%blank_nerd_tunnels))
{
	my @endpoints = $blank_nerd_tunnels{$blank_tun}->endpoint;
	my @address = $blank_nerd_tunnels{$blank_tun}->address;
	my @ass = $blank_nerd_tunnels{$blank_tun}->as;
	my $ip;
	my $ip_addy;
	my $other_as;
	my $as_name;
	my $as_num;
	my $blank_as='AS65023';
        my ($as1,$as2) = @ass;
	next if ((($as1 eq 'AS65000') and ($as2 eq 'AS65023')) or (($as2 eq 'AS65000') and ($as1 eq 'AS65023')));
	if ($as1 =~ /AS65023/m)
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

	$hosts .= qq[
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
	parents			$as_name
        check_command           check_ping_remote
        checks_enabled          1
        max_check_attempts      5
        notification_interval           30
        notification_period             24x7
        notification_options            d,u,r
        }
];
	$services .= qq[
define service{
        host_name               $as_name
        service_description     $as_name ping_remote
        check_command           check_ping_remote 
        max_check_attempts      5
        check_period            24x7
        normal_check_interval   15
        retry_check_interval    1
        notification_interval   30
        notification_period     24x7
        notification_options    w,c,r
        contact_groups          funknet-outside
        }
define service{
        host_name               ${as_name}-funknet
        service_description     ${as_name}-funknet ping_remote
        check_command           check_ping_remote 
        max_check_attempts      5
        check_period            24x7
        normal_check_interval   15
        retry_check_interval    1
        notification_interval   30
        notification_period     24x7
        notification_options    w,c,r
        contact_groups          funknet-inside
        }
];

	$hosts_inside .= "${as_name}-funknet,";
	$hosts_outside .= "$as_name,";
}

my $hostgroups_inside = qq[
define hostgroup{
        hostgroup_name          funknet-inside
        alias                   funknet-inside
        contact_groups          funknet-inside
        members                 $hosts_inside
}
];
my $hostgroups_outside = qq[
define hostgroup{
        hostgroup_name          funknet-outside
        alias                   funknet-outside
        contact_groups          funknet-outside
        members                 $hosts_outside
}
];

open(HOSTS,">hosts.cfg");
print HOSTS qq[
$hosts
];
close(HOSTS);

open(SERVICES,">services.cfg");
print SERVICES qq[
$services
];
close(SERVICES);

open(HOSTGROUPS,">hostgroups.cfg");
print HOSTGROUPS qq[
$hostgroups_inside
$hostgroups_outside
];
close(HOSTS);

exit 1;

