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


# "Programming Web Services with Perl", by Randy J. Ray and Pavel Kulchenko
# O'Reilly and Associates, ISBN 0-596-00206-8.
#
# The sample daemon class derived by sub-classing the
# SOAP::Transport::HTTP::Daemon class, which is in turn
# derived from HTTP::Daemon.
#
package Funknet::WebServices::IRR::Daemon;

use strict;
use vars qw(@ISA);
use Data::Dumper;
use SOAP::Transport::HTTP;
@ISA = qw(SOAP::Transport::HTTP::Daemon);

use Funknet::WebServices::IRR;

1;


sub request {

    my $self = shift;
    if (my $request = $_[0]) {
        my @cookies = $request->headers->header('cookie');
        %Funknet::WebServices::IRR::SOAP::COOKIES = ();
        for my $line (@cookies) {
            for (split(/; /, $line)) {
                next unless /(.*?)=(.*)/;
                $Funknet::WebServices::IRR::SOAP::COOKIES{$1} = $2;
            }
        }
    }
    $self->SUPER::request(@_);
}
