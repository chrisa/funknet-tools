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

package Funknet::Tools::Traceroute;
use strict;

use Funknet::Config::ConfigFile;
use Funknet::Config::CLI;
use Funknet::Config::Validate qw/ is_ipv4 /;

my $traceroute = '/usr/sbin/traceroute';

=head2 traceroute

This sub stolen from ztraceroute. Modified to use a persistent
connection to the zebra CLI.

Runs `which traceroute`, adds [ASnnnnn] to the output based on the
local Funknet router's view of the world.

=cut

my $cf;

sub traceroute {
    my ($address, $cb) = @_;
    unless (is_ipv4($address)) {
	return undef;
    }
    my $output;

    # must init ConfigFile first
    unless (defined $cf) {
	$cf = Funknet::Config::ConfigFile->new('/home/funknet/funknet-tools/funknet.conf-MUNKY');
    }
    my $cli = Funknet::Config::CLI->new()
      or return undef;
    $cli->login;
    
    open( TPIPE, "$traceroute -n $address 2>/dev/null|" )
      or die ("Cannot fork for traceroute: [$!]");
    
    $| = 1;
    
    while (<TPIPE>) {
	chomp;
	
	my ( $hop, $ip, $extra ) = /^\s*(\d+)\s+([\d\.]+)?\s+(.+)/;
	my ( $name, $asnum );
	if ($ip) {
	    #$name = gethostbyaddr( inet_aton($ip), AF_INET );
	    #$name = $ip unless $name;
	    $name = $ip;

	    $asnum = $cli->get_as($ip);
	    if ( $asnum && $asnum > 0 && $asnum < 65535 ) {
		$asnum = "[AS $asnum]";
	    }
	    else {
		$asnum = '';
	    }
	}
	else {
	    $ip = $name = $asnum = '';
	}
	
	my $line = sprintf( "%2i %s (%s) %s %s\n", $hop, $name, $ip, $asnum, $extra );
	if (defined $cb && $cb->can('print')) {
	    $cb->print($line);
	} else {
	    $output .= $line;
	}
    }
    
    $cli->logout;
    close TPIPE or die ('Close failed');
    return $output;
}

1;
