#!/usr/local/bin/perl
#
# $Id$
#
# Copyright (c) 2004
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
use Funknet::KeyStash::CertServer;
use Funknet::ConfigFile::CertServer;
use Getopt::Std;

my %opt;
getopts('gwsc:o:p:f:', \%opt);

my $config = Funknet::ConfigFile::CertServer->new($opt{f});
my $l = $config->local();

if ($opt{g}) {
    unless (defined $opt{c} && defined $opt{o} && defined $opt{p}) {
	print STDERR "need all of Common Name, Organisational Unit and Passphrase for gen+sign\n";
	exit 1;
    }
    my $cs = Funknet::KeyStash::CertServer->new($l->{ca_dir}, $l->{ca_name});
    my ($newkey, $newreq) = $cs->newreq( cn         => $opt{c},
					 ou         => $opt{o},
					 passphrase => $opt{p},
				       );
    my $newcert = $cs->sign( req          => $newreq,
			     capassphrase => $l->{ca_pass},
			   );
    unless ($newcert) {
	print STDERR "problem generating cert -- unique CN for this CA?\n";
	exit 1;
    }
    print "$newkey\n$newcert\n";
    
    if ($opt{w}) {
	my $object = $cs->object($newcert);
	print "$object\n";
    }
}

if ($opt{s}) {
    my $req;
    {
	local undef $/;
	$req = <STDIN>;
    }
    unless (defined $req) {
	print STDERR "need a CSR on stdin for sign\n";
	exit 1;
    }
    my $cs = Funknet::KeyStash::CertServer->new('etc/ca', 'TestCA');
    my $newcert = $cs->sign( req          => $req,
			     capassphrase => 'TestCA',
			   );
    print $newcert;
}
