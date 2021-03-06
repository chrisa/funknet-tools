#!/usr/bin/perl -w
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

tunnelspace-list.pl

=head1 DESCRIPTION

query the whois for all the assigned IPs within the tunnelspaces.

emits warnings if an address is assigned to more than one tunnel.

=head1 USAGE

just run it. debug on stderr.

=cut

use strict;

use Socket qw/inet_aton/;
use Net::Whois::RIPE;

my @tun_list = ();
my @addr_list = ();
my @as_list = @{get_as()};

foreach my $as (@as_list) {
    get_tunnels_from_as($as, \@tun_list);
}

foreach my $tun (@tun_list) {
    get_address_from_tunnel($tun, \@addr_list);
}

foreach my $addr (@addr_list) {
    check_inetnum($addr);
}

my @sorted = sort { inet_aton($a->{address}) cmp inet_aton($b->{address}) }
             @addr_list;

foreach my $sorted (@sorted) {
    pretty_print($sorted);
}

exit;

sub debug {
    print STDERR "[tunnelspace-list] @_\n";
}

sub error {
    print "[tunnelspace-list] FATAL @_\n";
    exit 1;
}

sub get_as {
    my @as_list;

    debug('get_as: creating N::W::R');
    my $whois = Net::Whois::RIPE->new('whois.funknet.org');
    $whois->type('as-set');

    debug('get_as: querying');
    my $transit = $whois->query('AS-FUNKTRANSIT');
    if (!defined $transit) {
	error('get_as failed');
    }

    foreach my $as ($transit->members) {
	if (!defined $as) { next; }
	debug("get_as: got $as");
	push @as_list, $as;
    }

    return(\@as_list);
}

sub get_tunnels_from_as {
    my ($as_name, $tun_list) = @_;

    debug("get_tunnels: creating N::W::R for as $as_name");
    my $whois = Net::Whois::RIPE->new('whois.funknet.org');
    $whois->type('aut-num');

    debug('get_tunnels: querying');
    my $as = $whois->query($as_name);
    if (!defined $as) {
	error("get_tunnels failed for $as_name");
    }

    foreach my $tunnel ($as->tun) {
	if (!defined $tunnel) { next; }
	if (! grep /^$tunnel$/, @$tun_list) {
	    debug("get_tunnels: unique $tunnel found in $as_name");
	    push @$tun_list, $tunnel;
	}
    }
}

sub get_address_from_tunnel {
    my ($tunnel_name, $addr_list) = @_;

    my $tunnel = get_tunnel($tunnel_name);
    if (!defined $tunnel) {
	error("get_address failed for $tunnel_name");
    }

    foreach my $address ($tunnel->address) {
	if (!defined $address) { next; }
	my @overlaps = grep {$_->{address} eq $address} @$addr_list;
	if (!scalar @overlaps) {    
	    debug("get_address: unique $address found in $tunnel_name");
	    push @$addr_list, { address => $address, tunnel => $tunnel_name };
	} else {
	    foreach my $overlap (@overlaps) {
	        debug("EEP: $address ($tunnel_name) overlaps with $overlap->{tunnel}");
	    }
	}
    }
}

sub get_inetnum {
    my ($addr) = @_;
    debug("get_inetnum: creating N::W::R for address $addr");
    my $whois = Net::Whois::RIPE->new('whois.funknet.org');
    $whois->type('inetnum');

    debug('get_inetnum: querying');
    my $inetnum = $whois->query($addr);
    return ($inetnum);
}

sub get_tunnel {
    my ($name) = @_;
    debug("get_tunnel: creating N::W::R for $name");
    my $whois = Net::Whois::RIPE->new('whois.funknet.org');
    $whois->type('tunnel');

    debug('get_tunnel: querying');
    my $tunnel = $whois->query($name);
    return ($tunnel);
}

sub check_inetnum {
    my ($addr) = @_;

    my $inetnum = get_inetnum($addr->{address});
    if (!defined $inetnum) {
	debug("EEP: can't obtain an intenum for $addr->{address}");
	return;
    }

    # don't think this can happen
    if (!defined $inetnum->netname) {
	debug("EEP: inetnum for $addr->{address} has no netname");
	return;
    }

    if ($inetnum->netname ne $addr->{tunnel}) {
	debug("EEP: tunnel   : $addr->{tunnel} ($addr->{address}) mismatches");
	debug("EEP: inetnum  : ".$inetnum->netname.' ('.$inetnum->inetnum.')');
	my $assign = get_inetnum($addr->{tunnel});
	if (defined $assign && defined $assign->inetnum) {
	    debug('EEP: assigned : '.$assign->inetnum);
	} else {
	    debug("EEP: no specific net assigned for $addr->{tunnel}");
	}
	return;
    }
}

sub pretty_print {
    my ($addr) = @_;

    format STDOUT =
@<<<<<<<<<<<<<<<    @<<<<<<<<<<<<<<<
$addr->{address},   $addr->{tunnel}
.

    write;
}
