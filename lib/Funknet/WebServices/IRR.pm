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


package Funknet::WebServices::IRR;
use strict;
use Data::Dumper;
# This module contains the code to drive RtConfig etc. 

use subs qw/ RtConfig /;
use Digest::MD5 'md5_hex';

1;

sub new {
    my ($class) = @_;

    print STDERR "in IRR::new\n";

    my $self = bless {}, $class;
    return $self;
}

sub RtConfig {
    my ($self, $dir, $source_as, $peer_as, $source_addr, $peer_addr) = @_;
    
    print Dumper \@_;

    my $rtconfig = 
	'/usr/local/bin/RtConfig -h whois.funknet.org -p 43 -s FUNKNET -protocol ripe ' . 
	'-config cisco -cisco_use_prefix_lists';

    my $command = 
	'@RtConfig '.$dir.' AS'.$source_as.' '.$source_addr.' AS'.
	$peer_as.' '.$peer_addr."\n";

    my @output = `echo '$command' | $rtconfig`;
    
    my $acl_text = '';
    my $acl_name;
    for my $line (@output) {
	next unless ($line =~ /^ip prefix-list/);
	$acl_name = $peer_as.$dir;
	$line =~ s/pl100/$acl_name/;
	$acl_text .= $line;
    }

    return "access-list failed" unless $acl_text;
    return $acl_text;
}

