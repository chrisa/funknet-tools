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


package Funknet::Tools::Whois;
use strict;
use IO::Socket::INET;

=head1 DESCRIPTION

A whois client, with HTML markup of useful-looking things.

=cut

sub whois {
    my ($q) = @_;
    
    my $sock = IO::Socket::INET->new(
				     PeerAddr => 'whois.funknet.org',
				     PeerPort => 43,
				     Proto    => 'tcp' );
    defined $sock or die "socket: $!";
	
    print $sock $q;
    print $sock "\n";
	
    my $result;
    while (<$sock>) {
	$result .= $_;
    }

    # wrap things that look useful into links back to us

    $result =~ s/([A-Z]+[0-9]+-FUNKNET)/<a href="whois\?q=$1">$1<\/a>/g;
    $result =~ s/(\d+\.\d+\.\d+\.\d+)/<a href="whois\?q=$1">$1<\/a>/g;
    $result =~ s/(AS\d+)/<a href="whois\?q=$1">$1<\/a>/g;
    $result =~ s/(AS-[A-Z]+)/<a href="whois\?q=$1">$1<\/a>/g;
    $result =~ s/(mnt-by:\s+)(.+)/$1<a href="whois\?q=$2">$2<\/a>/g;
    $result =~ s/(mnt-lower:\s+)(.+)/$1<a href="whois\?q=$2">$2<\/a>/g;
    $result =~ s/(tun:\s+)(.+)/$1<a href="whois\?q=$2">$2<\/a>/g;

    return $result;
}

1;
