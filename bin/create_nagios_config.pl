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
my $confdir = "/usr/local/funknet-tools";
my $hosts;
my $services;
my $hosts_inside;
my $hosts_outside;
my $host_template = qq[
        check_command           check_ping_remote
        checks_enabled          1
        max_check_attempts      5
        notification_interval   30
        notification_period     24x7
        notification_options    d,u,r
];
my $service_template = qq[
        check_command           check_ping_remote
        max_check_attempts      5
        check_period            24x7
        normal_check_interval   15
        retry_check_interval    1
        notification_interval   30
        notification_period     24x7
        notification_options    w,c,r
];

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
		$ip = shift(@endpoints) || die "no ip";
		my $tmp_addy = shift(@address);
		$ip_addy = shift(@address) || die "no ip_addy";
		$other_as = $as2;
	}
	elsif ($as2  =~ /AS65023/m)
	{
		$ip = shift(@endpoints) || die "no ip";
		$ip_addy = shift(@address) || die "no ip_addy";
		$other_as = $as1;
	}
	$endpoints{$other_as} = $ip;
	$as_name=$as_names{$other_as} || die "no as_name";
	$as_num=$as_nums{$as_name} || die "no as_num";

	$hosts .= qq[
define host{
        host_name               $as_name
        alias                   $as_num
        address                 $ip
        $host_template}
define host{
        host_name               ${as_name}-funknet
        alias                   $as_num
        address                 $ip_addy
	parents			$as_name
        $host_template}];

	$services .= qq[
define service{
        host_name               $as_name
        service_description     $as_name ping_remote
        contact_groups          funknet-outside
        $service_template}
define service{
        host_name               ${as_name}-funknet
        service_description     ${as_name}-funknet ping_remote
        contact_groups          funknet-inside
        $service_template}];

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

my $contactgroups = qq[
define contactgroup{
        contactgroup_name       funknet-outside
        alias                   funknet
        members                 FUNKNET
}

define contactgroup{
        contactgroup_name       funknet-inside
        alias                   funknet
        members                 FUNKNET
}
];

open(HOSTS,">$confdir/hosts.cfg"); print HOSTS qq[$hosts]; close(HOSTS);
open(SERVICES,">$confdir/services.cfg"); print SERVICES qq[$services]; close(SERVICES);
open(CONTACTGROUPS,">$confdir/contactgroups.cfg"); print CONTACTGROUPS qq[$contactgroups]; close(CONTACTGROUPS);
open(HOSTGROUPS,">$confdir/hostgroups.cfg"); print HOSTGROUPS qq[$hostgroups_inside\n$hostgroups_outside]; close(HOSTS);

# add conf for non-whois hosts, or exit if there is none

opendir(DIR, "$confdir/nagios") || usage();
my $d_ent;
my @d_ents;
while(defined($d_ent=readdir(DIR))) {
    next if $d_ent eq ".";
    next if $d_ent eq "..";
    push(@d_ents, $d_ent);
}
closedir(DIR);

foreach my $network (@d_ents) {
    print STDERR ">>> $network\n";
    my $host_names;

    $contactgroups = qq[
define contactgroup{
        contactgroup_name       $network
        alias                   $network network
        members                 FUNKNET
}
];

    open(CONTACTGROUPS,">>$confdir/contactgroups.cfg"); print CONTACTGROUPS qq[$contactgroups]; close(CONTACTGROUPS);

    open(NAGIOSCONF,"<$confdir/nagios/$network") || usage();
    $hosts = "";
    $services = "";
    while (<NAGIOSCONF>) {
        chomp;
        print STDERR "$_\n";
        my ($host_name,$address,$parent) = split / /,$_;
        (my $alias = $host_name) =~ s/\..*//;
        $parent = $network unless defined($parent);
    
        $host_names .= "$host_name,";

        $hosts .= qq[
define host{
        host_name               $host_name
        alias                   $alias
        address                 $address
        parents                 $parent
        $host_template}];
    
        $services .= qq[
define service{
        host_name               $host_name
        service_description     $host_name ping_remote
        contact_groups          $network
        $service_template}];
    
    }

    close(NAGIOSCONF);

    $hostgroups_inside = qq[
define hostgroup{
        hostgroup_name          $network
        alias                   $network network
        contact_groups          $network
        members                 $host_names
}
];

    open(HOSTGROUPS,">>$confdir/hostgroups.cfg"); print HOSTGROUPS qq[$hostgroups_inside\n]; close(HOSTS);
    open(HOSTS,">>$confdir/hosts.cfg"); print HOSTS qq[$hosts\n]; close(HOSTS);
    open(SERVICES,">>$confdir/services.cfg"); print SERVICES qq[$services\n]; close(SERVICES);
    
}

exit 1;

sub usage {
    print STDERR qq[
this script autogenerates nagios config files:

	hosts.cfg
	hostgroups.cfg
	services.cfg
	contactgroups.cfg

...based on info in whois.funknet.org FUNKNET whois database used by funknet-tools.

to monitor hosts on FUNKNET whith no whois data, ie, those hosts behind FUNKNET nerds,
please create ./nagios/ in this directory and populate with files like this:

# cat ./nagios/NETDOTNET-funknet
consume.netdotnet.funknet.org 192.168.9.6
dell.netdotnet.funknet.org 192.168.9.253
naught.netdotnet.funknet.org 192.168.9.3
null.netdotnet.funknet.org 192.168.10.2 naught.netdotnet.funknet.org
atom.netdotnet.funknet.org 192.168.10.4 naught.netdotnet.funknet.org
farst.netdotnet.funknet.org 192.168.10.5 naught.netdotnet.funknet.org
prefect.netdotnet.funknet.org 192.168.10.6 naught.netdotnet.funknet.org
#

... the format being '<hostname> <ip_addr> [<parent>]
where parent defaults to the FUNKNET nerd ( NETDOTNET-funknet )
if not specified.

the contact group created is network specific, with FUNKNET as the only member,
this can be added to by editting the nagios contacts.cfg file
(untouched by this script)

to ditch this error message, either make use of ./nagios/ or,
runme >/dev/null 2>&1

:)

];
    exit 1;
}
