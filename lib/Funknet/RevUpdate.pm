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

package Funknet::RevUpdate;
use strict;
use Data::Dumper;

=head1 NAME

Funknet::RevUpdate

=head1 DESCRIPTION

A reverse-dns update robot, after 'Marvin', the RIPE robot. 

=cut

use Net::DNS;
use vars qw/ @EXPORT_OK @ISA /;
@EXPORT_OK = qw/ do_update check_delegate /;
@ISA = qw/ Exporter /;
use Exporter; 

my @auth_zones = qw/ 10.in-addr.arpa 16.172.in-addr.arpa 168.192.in-addr.arpa /;

=head2 check_delegate

The delegation check - we query the nameservers we're being asked to delegate
to for the NS record for the domain we're trying to delegate, to avoid lameness.

=cut

sub check_delegate {

    my ($rev_zone, @ns) = @_;

    my $res = Net::DNS::Resolver->new;

    my $ok;
    for my $ns (@ns) {
	$res->nameservers($ns);
	my $query = $res->query($rev_zone, 'NS');
	
	my @results;
	if ($query) {
	    foreach my $rr (grep { $_->type eq 'NS' } $query->answer) {
		push @results, $rr->nsdname;
	    }
	} else {
	    print STDERR "query failed: ", $res->errorstring, "\n";
	} 

	# the list @results should be the same as @ns. 
	    
	print STDERR Dumper { ns => \@ns, results => \@results };	
	
	if ((join /-/,sort @ns) eq (join /-/,sort @results)) {
	    print STDERR "match for $ns\n";
	    $ok++;
	}
    }
    if ($ok == scalar @ns) {
	print STDERR "returning ok";
	return 1;
    } else {
	print STDERR "returning not ok";
	return undef;
    }
}

=head2 do_update

Actually perform the ddns update. Assumes everything is good to go.

=cut


sub do_update {
    
    # we expect: zone to delegate, nameservers to delegate to. 
    my ($rev_zone, @ns) = @_;
    
    # get the zone this is in.

    my $auth;
    for my $zone (@auth_zones) {
	if ($rev_zone =~ /$zone$/) {
	    $auth = $zone;
	    last;
	}
    }
    unless (defined $auth) {
	return undef;
    }
    
    my $update = Net::DNS::Update->new($auth);
    
    # Prerequisite is that no A records exist for the name.
    #$update->push("pre", nxrrset("foo.example.com. A"));
    
    for my $ns (@ns) {
	$update->push("update", rr_add("$rev_zone 86400 NS $ns"));
    }
    
    # Send the update to the zone's primary master.
    my $res = Net::DNS::Resolver->new;
    $res->nameservers("munky.nodnol.org");
    
    my $reply = $res->send($update);
    
    # Did it work?
    if (defined $reply) {
            if ($reply->header->rcode eq "NOERROR") {
                print STDERR "Update succeeded\n";
		return 1;
        } else {
            print STDERR "Update failed: ", $reply->header->rcode, "\n";
	    return undef;
            }
    } else {
        print STDERR "Update failed: ", $res->errorstring, "\n";
	return undef;
    } 
}
