#
# $Id$
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

package Funknet::Whois::Policy;
use strict;

use vars qw/ @EXPORT_OK @ISA /;
@ISA = qw/ Exporter /;
@EXPORT_OK = qw/ assign_as assign_tunnel_inetnum /;
use Exporter;

use Funknet::Whois qw/ get_object /;
use Funknet::Whois::DirectMysql;

=head1 NAME

Funknet::Whois::Policy

=head1 DESCRIPTION

Contains functions to allocate networks from larger networks,
following policy hints in the larger networks' objects, and to assign
AS numbers. Intended to be used by the ObjectGenerator functionality.

=head1 FUNCTIONS

=head2 assign_as

Returns an available AS number. As currently implented returns the
*next* available AS number, although the only guarantee is the the AS
was not in use at the time of the query.

Does not take any notice of AS blocks.

=cut

sub assign_as {
    
    my $dbh = new Funknet::Whois::DirectMysql;
    
    my $sql = "SELECT SUBSTRING(aut_num, 3) AS aut_num
                 FROM aut_num 
             ORDER BY aut_num DESC
                LIMIT 1";

    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute();
    unless ($rv) {
	warn "database: $DBI::errstr";
	return undef;
    }
    my ($as) = $sth->fetchrow_array;
    $sth->finish;
    
    return 'AS'.($as + 1);    
}

=head2 assign_tunnel_inetnum

Takes a peer AS as 'AS\d+', which is assumed to be a central node to
which a tunnel allocation has been made, named '$node-TUNNELS'. 

Selects a /30 inetnum from the allocation made to that central node,
and returns a string suitable for the 'inetnum:' field of the object,
i.e. "10.2.0.0 - 10.2.0.3".

=cut

sub assign_tunnel_inetnum {
    my ($peer) = @_;
    unless ($peer =~ /^AS\d+$/) {
	return undef;
    }

    # get aut-num for our peer
    my $aut_num = get_object('aut-num', $peer);
    
    # get tunnelspace inetnum allocation
    my $netname = $aut_num->as_name . '-TUNNELS';
    my $tspace = get_object( 'inetnum', $netname );
    my $inum = $tspace->inetnum;

    my $dbh = new Funknet::Whois::DirectMysql;
	
    my ($alloc_start, $alloc_end);
    if ($inum =~ /(.*) - (.*)/) {
	($alloc_start, $alloc_end) = ($dbh->ipv4_to_int($1), $dbh->ipv4_to_int($2));
    } else {
	warn "inetnum didn't parse";
	return undef;
    }
    
    # find highest inetnum in this allocation
    my $sql = "SELECT begin_in, end_in 
                 FROM inetnum 
                WHERE begin_in > ?
                  AND end_in < ?
             ORDER BY end_in DESC
                LIMIT 1";

    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($alloc_start, $alloc_end);
    unless ($rv) {
	warn "database: $DBI::errstr";
	return undef;
    }
    my ($tun_start, $tun_end) = $sth->fetchrow_array;
    $sth->finish;
    
    # return the /30 following this
    
    $tun_start += 4;
    $tun_end += 4;
    
    if ($tun_start >= $alloc_start && $tun_end <= $alloc_end) {
	my $start_ip = $dbh->int_to_ipv4($tun_start);
	my $end_ip = $dbh->int_to_ipv4($tun_end);

# XXX return an inetnum or a cidr network?
	my $tun_inum = "$start_ip/30";
        return $tun_inum;
    } else {
	warn "assignment full?";
	return undef;
    }
}

1;
