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

package Funknet::Whois;
use strict;

=head1 NAME

Funknet::Whois

=head1 DESCRIPTION

Routines for dealing with whois objects.
   
=cut

use vars qw/ @EXPORT_OK @ISA /;
@EXPORT_OK = qw/ parse_object check_auth object_exists get_object pretty_object /;
@ISA = qw/ Exporter /;
use Exporter; 

use IO::Scalar;
use Net::Whois::RIPE;
use Net::Whois::RIPE::Object;
use Funknet::Whois::Object;

=head2 parse_object

Takes a whois object as text, returns a Net::Whois::RIPE::Object
object (this is only here because the Net::Whois::RIPE::Object
constructor expects a handle, and we have a string).

Yeah, this should probably proxy through a Funknet::Whois::Object 
constructor.

=cut

sub parse_object {
    my ($object_text) = @_;
    my $sh = new IO::Scalar \$object_text;
    my $object = Net::Whois::RIPE::Object->new($sh);
    return bless $object, 'Funknet::Whois::Object';
}

=head2 check_auth

Takes a zone and a keyid and checks that that key is authorised to
delegate that zone for reverse dns. We do this by converting the 
'domain' attribute we're passed into an inetnum and retrieving the
corresponding object. We then get the mntner for that inetnum, and
check that the keyid we've been given is in the list of keys on that
mntner.  

=cut

sub check_auth {
    my ($zone, $keyid) = @_;

    $keyid =~ s/.*([A-F0-9]{8})$/$1/;

    my $inetnum;
    if 
	($zone =~ /(\d+).(\d+).(\d+).in-addr.arpa/) {
	    $inetnum = "$3.$2.$1.0";
    } 
    elsif 
	($zone =~ /(\d+).(\d+).in-addr.arpa/) {
	    $inetnum = "$2.$1.0.0";
	}

    my $w = Net::Whois::RIPE->new( 'whois.funknet.org' );
    $w->type('inetnum');
    my $in = $w->query($inetnum);
    
    my $auth_ok;
  AUTH:
    for my $mnt_by ($in->mnt_by) {

	$w->type('mntner');
	my $mntner = $w->query($mnt_by);
	
	for my $auth ($mntner->auth) {

	    if ($auth eq "PGPKEY-$keyid") {
		$auth_ok = 1;
		last AUTH;
	    }
	}
    }
	    
    return $auth_ok;
}
    
sub object_exists {
    my ($object) = @_;
    ref $object eq 'Net::Whois::RIPE::Object' or return undef;

    # check type, extract primary key.

    # do lookup

    # prune whitespace

    # compare

    return 1;
}

sub get_object {
    my ($type, $name) = @_;
    my $w = Net::Whois::RIPE->new( 'whois.funknet.org' );
    $w->type($type);
    my $obj = $w->query($name);
    if (scalar @{ $obj->{_order} }) {
        return $obj;
    } else { 
	return undef;
    }
}

1;
