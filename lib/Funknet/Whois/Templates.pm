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

package Funknet::Whois::Templates;
use strict;

use vars qw/ @EXPORT_OK @ISA /;
@EXPORT_OK = qw/ tmpl /;
@ISA = qw/ Exporter /;
use Exporter;

=head1 NAME

Funknet::Whois::Templates

=head1 DESCRIPTION

Templates for the whois db.

=cut

my $t;

sub tmpl {
    my ($type) = @_;
    return $t->{$type};
}
 
$t->{person} = '
person:
address:
phone:
fax-no:
e-mail:
nic-hdl:
remarks:
notify:
mnt-by:
changed:
source:
';

$t->{mntner} = '
mntner:
descr:
admin-c:
tech-c:
upd-to:
mnt-nfy:
auth:
remarks:
notify:
mnt-by:
referral-by:
changed:
source:
';

$t->{'key-cert'} = '
key-cert:
method:
owner:
fingerpr:
certif:
remarks:
notify:
mnt-by:
changed:
source:
';


1;
