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

use Funknet::RevUpdate::Robot;
use Funknet::RevUpdate        qw/ do_update check_delegate /;
use Funknet::Whois            qw/ parse_object check_auth /;
use PGP::Mail;

my $testing = 1; # getopt

# parse mail, check sig.

my $data;
my $line = <STDIN>;
if($line && $line !~ /^From /) {
    $data .= $line;
}
while(read(STDIN, $line, 8192)) {
    $data .= $line;
}

my $robot = Funknet::RevUpdate::Robot->new( envfrom => 'auto-inaddr@funknet.org',
					    from    => 'auto-inaddr@funknet.org',
					    pubring => '/home/funknet/.gnupg/pubring.gpg',
					    secring => '/home/funknet/.gnupg/secring.gpg',
					    testing => $testing,
					  );

unless ($robot->process_header($data)) {
    errorlog("error reading header -- a bounce?");
    exit 0;    
}

# check pgp sig

my $pgp;
unless ($pgp = $robot->check_sig($data)) {
    $robot->fatalerror("no valid and known signature found");
}

# attempt to create a Net::Whois::RIPE::Object

my $object;
unless ($object = parse_object($pgp->data)) {
    $robot->fatalerror("couldn't convert the signed message into a Net::WHOIS::RIPE::Object");
}

# check authorisation against whois.

unless (check_auth($object->domain, $pgp->keyid)) {
    $robot->error("hierarchical authorisation failed");
}

# extract zone, nameservers from object.

my $zone = $object->domain;
my @ns = $object->rev_srv;

# check delegation

unless (check_delegate($zone, @ns) ) {
    $robot->error ("delegation check failed: " . Funknet::RevUpdate::errors );
}

# actually do the update, if we're error-free

# XXX don't just do_update anyway...

do_update($zone, @ns);

my $mail_text;
if ($robot->error) {
    $mail_text = $robot->failure_text($zone, @ns);
} else {
    $mail_text = $robot->success_text($zone, @ns);
}

# reply 

unless (my $res = $robot->reply_mail( $mail_text, subject => 'Reverse Delegation results' )) {
    errorlog("error sending mail: $res");
    exit 1;
}


sub errorlog {
    my ($log_text) = @_;
    print STDERR $log_text;
}

