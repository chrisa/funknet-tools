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

package Funknet::Tools::Ping;
use strict;

=head1 NAME

Funknet::Tools::Ping

=head1 DESCRIPTION

A wrapper for 'nping', to do Cisco-style pings. 

Call ping with at least the address, which must be an IPv4
dotted-quad. Anything else gets undef back. 

If you also pass an object which ->can('print') then for each line of
output from the ping tool, this method will be called. That object
might be an Apache response object, say.

Whatever, the entire output (nping's stdout) is returned. stderr is
thrown away. The exit status is ignored, as 100% packet loss gives a
non-zero status, which isn't really what you want. 

=cut

use Funknet::Config::Validate qw/ is_ipv4 /;

# use 'nikhef ping' for cisco style
my $ping = '/usr/local/bin/nping';

=head2 ping 

Runs nikhef_ping for the tools section of funknet.org

=cut

sub ping {
    my ($address, $cb) = @_;
    unless (is_ipv4($address)) {
	return undef;
    }
    my $output;

    open( PPIPE, "$ping -t 2 -k 5 -c $address 2>/dev/null|" )
      or die ("Cannot fork for ping: [$!]");
    
    $| = 1;
    
    while (my $line = <PPIPE>) {
	# might want to alter the output a bit here?
	
	if (defined $cb && $cb->can('print')) {
	    $cb->print($line);
	} else {
	    $output .= $line;
	}
    }
    close PPIPE;
    return $output;
}

1;
