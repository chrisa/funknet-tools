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

inetnum-list.pl

=head1 DESCRIPTION

query the whois for all the inetnums and sort them so that:

   numerically lower nets are first
   smaller nets come before ones which include them

=head1 USAGE

just run it. debug on stderr.

=cut

use strict;

use Socket qw/inet_aton/;
use Net::Whois::RIPE;
use Net::Netmask;

my $inets = query();
$inets = sortnets($inets);
foreach my $inet (@$inets) {
    pretty_print ($inet);
}

exit;

sub debug {
    print STDERR "[inetnum-list] @_\n";
}

sub query {
    debug('query: creating N::W::R');
    my $whois = Net::Whois::RIPE->new('whois.funknet.org');
    $whois->type('inetnum');
    $whois->find_all_more;

    my @inets;
    debug('query: querying');
    foreach my $inet ($whois->query('0.0.0.0/0')) {
	if (defined $inet && defined $inet->inetnum) {
	    push @inets, $inet;
	    debug('query: received '.$inet->inetnum);
	}
    }

    return(\@inets);
}

sub sortnets {
    my ($inets) = @_;
    my (@munge, @sorted);

    # associate a net::netmask to each inetnum before we sort
    # use a map instead?
    foreach my $inets (@$inets) {
	my $inet = $inets->inetnum;
	my $nn = new Net::Netmask ($inet);
	push @munge, { nn => $nn, inetnum => $inets };
    }

    @sorted = sort compare @munge;

    # get back to the inetnums
    @$inets = ();
    foreach my $sorted (@sorted) {
	push @$inets, $sorted->{inetnum};
    }
    return ($inets);
}

# sort the numerically lower subnet before the numerically higher
# sort the smaller subnet before the large inclusive one
sub compare {
    # is it inclusive?
    my $a_base = $a->{nn}->base;
    my $b_base = $b->{nn}->base;
    if ($b->{nn}->match($a_base)) {
	# inclusive leftways
	debug('compare: inclusive '.$a->{inetnum}->inetnum.' < '.$b->{inetnum}->inetnum);
	return -1;
    } elsif ( $a->{nn}->match($b_base)) {
       # inclusive rightways
	debug('compare: inclusive '.$a->{inetnum}->inetnum.' > '.$b->{inetnum}->inetnum);
	return 1;
    } else {
	my $r = inet_aton($a_base) cmp inet_aton($b_base);
	debug('compare: '.$a->{inetnum}->inetnum ." $r ".
			  $b->{inetnum}->inetnum);

	return $r;
    }
}

sub pretty_print {
    my ($inet) = @_;

    format STDOUT =
@<<<<<<<<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$inet->netname, ('('.$inet->mnt_by.')'),      $inet->inetnum
.
    write;
}
