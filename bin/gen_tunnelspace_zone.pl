#!/usr/local/bin/perl -w
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

=head1 NAME

gen_tunnelspace_zone.pl

=head1 DESCRIPTION

generate a zonefile for a central node's tunnelspace allocation. 

=head1 USAGE

one arg, the central node's name. 

=cut

use strict;
use Net::Whois::RIPE;
use Socket qw/inet_aton/;
use Data::Dumper;

my $cnode_name;
unless (scalar @ARGV == 1) {
    print STDERR "usage: $0 <cnode name>\n";
    exit 1;
} else {
    $cnode_name = $ARGV[0];
}

# get central node's AS from name, using inet-rtr object

my $w = Net::Whois::RIPE->new('whois.funknet.org');
$w->type('inet-rtr');
my $rtr = $w->query($cnode_name);
if (!defined $rtr) {
    print STDERR "couldn't find inet-rtr for $cnode_name\n";
    exit 1;
}
my $cnode_as = $rtr->local_as;

# get list of tunnels from AS
$w->type('aut-num');
my $as = $w->query($cnode_as);
if (!defined $as) {
    print STDERR "couldn't find aut-num for $cnode_as ($cnode_name)\n";
    exit 1;
}

# get the tunnelspace zone for this cnode
# doesn't matter if it fails.
$w->type('inetnum');
my $inetnum = $w->query($cnode_name.'-TUNNELS');
my ($zone_lo, $zone_hi);
if (defined $inetnum) {
    my $cnode_zone = $inetnum->inetnum;
    ($zone_lo, $zone_hi) = $cnode_zone =~ /(.*) - (.*)/;
    ($zone_lo, $zone_hi) = (inet_aton($zone_lo), inet_aton($zone_hi));
}

# for each tunnel, create name/address pair for each end
my @zone;
my $as_names;
for my $tun ($as->tun) {
    $w->type('tunnel');
    my $tun_obj = $w->query($tun);
    unless (defined $tun_obj) {
	print STDERR "no tunnel object for $tun, continuing\n";
	next;
    }
    my @as = $tun_obj->as;
    my @ip = $tun_obj->address;

    for my $i (0 .. 1) {
	# check this is within our zone
	my $int_ip = inet_aton($ip[$i]);
	next unless ($int_ip ge $zone_lo && $int_ip le $zone_hi); 
	
	# fetch as name if needed
	if (!exists $as_names->{$as[$i]}) {
	    $as_names->{$as[$i]} = get_as_name($as[$i]);
	}
	
	# make zonefile entries
	my @o = $ip[$i] =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
	push @zone, { 
		     address     => $ip[$i],
		     fullname    => lc($as_names->{$as[$i]}) . '.' . lc($tun_obj->tunnel) . '.' . lc($cnode_name) . '.tun.funknet.org',
		     forwardname => lc($as_names->{$as[$i]}) . '.' . lc($tun_obj->tunnel),
		     forwardzone => lc($cnode_name) . '.tun.funknet.org',
		     reversename => $o[3],
		     reversezone => "$o[2].$o[1].$o[0].in-addr.arpa",
		    };
    }
}

output_forward_zone(lc($cnode_name) . '.tun.funknet.org', @zone);
output_reverse_zone(@zone);




sub output_forward_zone {
    my ($zone, @zone) = @_;
    my ($forwardname, $address);

    my $header = "\$TTL 86400
$zone. 86400 IN      SOA munky.nodnol.org.   hostmaster.nodnol.org. (
                2004030301
                7200
                3600
                2222222
                7200    )

@               ns      munky.nodnol.org.
localhost       IN      A       127.0.0.1

";

    format FORWARD =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   IN A  @<<<<<<<<<<<<<<<
$forwardname,                             $address
.
    
    my $filename = $zone . '.zone';
    open FORWARD, ">$filename"
      or die "can't open $filename for writing: $!";
    print FORWARD $header;

    select FORWARD;
    $~ = "FORWARD";
    
    for my $zone (@zone) {
	$forwardname = $zone->{forwardname};
	$address     = $zone->{address};
	write;
    }
}



sub output_reverse_zone {
    my (@zone) = @_;
    my $zone = $zone[0]->{reversezone};
    my ($reversename, $fullname);

    my $header = "\$TTL 86400
$zone. 86400 IN      SOA munky.nodnol.org.   hostmaster.nodnol.org. (
                2004030301
                7200
                3600
                2222222
                7200    )

@               ns      munky.nodnol.org.
localhost       IN      A       127.0.0.1

";

    format REVERSE =
@<<<<<<<<  IN PTR  @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$reversename,      $fullname
.
    
    my $filename = $zone . '.zone';
    open REVERSE, ">$filename"
      or die "can't open $filename for writing: $!";
    print REVERSE $header;

    select REVERSE;
    $~ = "REVERSE";
    
    for my $zone (@zone) {
	$reversename = $zone->{reversename};
	$fullname    = $zone->{fullname} . '.';
	write;
    }
}



sub get_as_name {
    my ($as) = @_;
    return undef unless defined $as;
    
    $w->type('aut-num');
    my $aut_num = $w->query($as);
    return undef unless defined $aut_num;
    
    my $as_name = $aut_num->as_name;
    return $as_name;
}
