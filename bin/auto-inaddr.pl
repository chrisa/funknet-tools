#!/usr/local/bin/perl
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

use strict;
use lib './lib';

=head1 NAME

auto-inaddr.pl

=head1 DESCRIPTION

Implement the auto-inaddr@funknet.org reverse delegation robot.

* parse mail - check sig, extract object.
* extract the zone and nameservers from the object
* check the keyid is listed on the mntner of the inetnum to which
  this reverse delegation applies.
* check the new nameservers have the relevant zone
* do the delegation

=cut

use Funknet::RevUpdate qw/ do_update check_delegate /;
use Funknet::Whois     qw/ parse_object check_auth /;
use PGP::Mail;


my $keyring = '/home/funknet/.gnupg/keyring';

# parse mail, check sig.

my $data;
my $line = <STDIN>;
if($line && $line !~ /^From /) {
    $data .= $line;
}
while(read(STDIN, $line, 8192)) {
    $data .= $line;
}

$pgpargs =
{
    "no_options" => 1,
    "extra_args" =>
	[
	 "--no-default-keyring",
	 "--no-auto-check-trustdb",
	 "--keyring" => $keyring,
	 "--secret-keyring" => $keyring.".sec",
	 "--keyserver-options" => "no-auto-key-retrieve",
	],
	"always_trust" => 1,
};

my $pgp = new PGP::Mail($data, $pgpargs);
unless ($pgp->status eq "good") {
    error("no valid and known signature found");
}

my $keyid = $pgp->keyid;
my $object_text = $pgp->data;
my $object = parse_object($object_text);

# check authorisation against whois.

unless (check_auth($object->domain, $pgp->keyid)) {
    error("hierarchical authorisation failed");
}

# extract zone, nameservers from object.

my $zone = $object->domain;
my @ns = $object->rev_srv;

# check delegation, do update.

unless (check_delegate($zone, @ns) ) {
    error ("delegation check failed: " . Funknet::RevUpdate::errors );
}

do_update($zone, @ns);


sub error {
    my ($error_text) = @_;

    # send mail with error_text, log problem. 

}
