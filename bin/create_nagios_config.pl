#!/usr/bin/perl -w

# $Id: 
#
# Copyright (c) 2003
#	The funknet.org Group.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#	This product includes software developed by The funknet.org
#	Group and its contributors.
# 4. Neither the name of the Group nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE GROUP AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE GROUP OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

use strict;
use lib './lib';
use Funknet::Config;
use Funknet::Debug;
use Funknet::Whois;
#use Funknet::Whois::Client;
use Getopt::Std;
#use Nagios::Config; # no need for this yet
use Data::Dumper;

=head1 NAME

config.pl

=head1 DESCRIPTION

This script generates nagios config for checking nodes are alive. It is meant for centralnodes.

=head1 OPTIONS

=head2 -f <config file location>

Specify the config file location.

=head2 -t <TRANSIT> (defaults to AS-FUNKTRANSIT)

Turn on copious debugging information

=cut

my %opt;
getopts('f:', \%opt);

unless ($opt{f}) {
    print STDERR "usage: $0 -f path_to_config_file\n";
    exit(1);
}
unless (-f $opt{f}) {
    print STDERR "-f option requires a path to a readable funknet.conf file\n";
    exit(1);
}

my $config = Funknet::ConfigFile->new( $opt{f} );

my $whois_source = $config->whois_source;
my $whois_host = $config->whois_host;
my $whois_port = $config->whois_port;
my $local_as = $config->local_as;
my $local_endpoint = $config->local_endpoint;
my $confdir = $config->nagios_config_dir;
my $transit = $opt{t} ? $opt{t} : "AS-FUNKTRANSIT";

my @as_names;
my @done;
my %nerd_autnum_objects;
my %cnerd_nerd_tunnels;
my %as_names;
my %as_nums;
my %endpoints;
my %nerd_tunnels;
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

my $whois = Funknet::Whois::Client->new($whois_host, Port => $whois_port);
unless (defined $whois)
{ 
        die "Error getting a Funknet::Config::Whois object\n";
}


$whois->type("as-set");
my $transobj = $whois->query("$transit");

foreach my $thing ($transobj->members)
{
#	next if (($thing eq "AS65000") or ($thing eq "$local_as"));
	next if ($thing eq "$local_as");
	$whois->type('aut-num');
	my $reply = $whois->query($thing);
	$nerd_autnum_objects{$thing} = $reply;
	$as_names{$thing} = $reply->as_name;
	$as_nums{$reply->as_name} = $thing;
}

$whois->type('aut-num');
my $cnerd_aut_num = $whois->query("$local_as");

foreach my $thing ($cnerd_aut_num->tun)
{
		$whois->type('tunnel');
		my $tun = $whois->query($thing);
		$cnerd_nerd_tunnels{$thing} = $tun;		
}

foreach my $cnerd_tun (keys(%cnerd_nerd_tunnels))
{
	my @endpoints = $cnerd_nerd_tunnels{$cnerd_tun}->endpoint;
	my @address = $cnerd_nerd_tunnels{$cnerd_tun}->address;
	my @ass = $cnerd_nerd_tunnels{$cnerd_tun}->as;
	my $ip;
	my $ip_addy;
	my $other_as;
	my $as_name;
	my $as_num;
        my ($as1,$as2) = @ass;
#	next if ((($as1 eq 'AS65000') and ($as2 eq 'AS65023')) or (($as2 eq 'AS65000') and ($as1 eq 'AS65023')));
	if ($as1 =~ /$local_as/m)
	{ 
		my $tmp = shift(@endpoints);
		$ip = shift(@endpoints) || die "no ip";
		my $tmp_addy = shift(@address);
		$ip_addy = shift(@address) || die "no ip_addy";
		$other_as = $as2;
	}
	elsif ($as2  =~ /$local_as/m)
	{
		$ip = shift(@endpoints) || die "no ip";
		$ip_addy = shift(@address) || die "no ip_addy";
		$other_as = $as1;
	}
	$endpoints{$other_as} = $ip;
	unless ($as_name=$as_names{$other_as}) {
                warn "skipping $cnerd_tun because its as-num is not in $transit\n";
                next
        }
	$as_num=$as_nums{$as_name} || die "no as_num";

	$hosts .= qq[
define host{
        host_name               $as_name
        alias                   $as_num
        address                 $ip
        $host_template}
define host{
        host_name               ${as_name}-${whois_source}
        alias                   $as_num
        address                 $ip_addy
	parents			$as_name
        $host_template}];

	$services .= qq[
define service{
        host_name               $as_name
        service_description     $as_name ping_remote
        contact_groups          ${whois_source}-outside
        $service_template}
define service{
        host_name               ${as_name}-${whois_source}
        service_description     ${as_name}-${whois_source} ping_remote
        contact_groups          ${whois_source}-inside
        $service_template}];

	$hosts_inside .= "${as_name}-${whois_source},";
	$hosts_outside .= "$as_name,";
}

my $hostgroups_inside = qq[
define hostgroup{
        hostgroup_name          ${whois_source}-inside
        alias                   ${whois_source}-inside
        contact_groups          ${whois_source}-inside
        members                 $hosts_inside
}
];
my $hostgroups_outside = qq[
define hostgroup{
        hostgroup_name          ${whois_source}-outside
        alias                   ${whois_source}-outside
        contact_groups          ${whois_source}-outside
        members                 $hosts_outside
}
];

my $contactgroups = qq[
define contactgroup{
        contactgroup_name       ${whois_source}-outside
        alias                   ${whois_source}
        members                 $whois_source
}

define contactgroup{
        contactgroup_name       ${whois_source}-inside
        alias                   ${whois_source}
        members                 $whois_source
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
        members                 $whois_source
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

# cat ./nagios/NETDOTNET-FUNKNET
consume.netdotnet.funknet.org 192.168.9.6
dell.netdotnet.funknet.org 192.168.9.253
naught.netdotnet.funknet.org 192.168.9.3
null.netdotnet.funknet.org 192.168.10.2 naught.netdotnet.funknet.org
atom.netdotnet.funknet.org 192.168.10.4 naught.netdotnet.funknet.org
farst.netdotnet.funknet.org 192.168.10.5 naught.netdotnet.funknet.org
prefect.netdotnet.funknet.org 192.168.10.6 naught.netdotnet.funknet.org
#

... the format being '<hostname> <ip_addr> [<parent>]
where parent defaults to the FUNKNET nerd ( NETDOTNET-FUNKNET )
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
