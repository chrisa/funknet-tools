#!/usr/local/bin/perl -w
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

# this script is awful. it predates me knowing about Net::Whois::RIPE. 
# it works though. 

use strict;

use GraphViz;
use IO::Socket::INET;
use Data::Dumper;

my $g = GraphViz->new(layout => 'neato',
		      no_overlap => 1,
		      directed => 0 );

my $central = $ARGV[0];

my $sock = IO::Socket::INET->new( PeerAddr => '62.169.139.122',
				  PeerPort => 43,
				  Proto    => 'tcp',
				);
print $sock $central;
print $sock "\n";

while (my $line = <$sock>) {
    next unless ($line =~ /^members: +(AS\d+)/);
    my $as = $1;
    
#    print STDERR "adding $as\n";
#    $g->add_node($as);
    
    my $as_sock = IO::Socket::INET->new( PeerAddr => '62.169.139.122',
					 PeerPort => 43,
					 Proto    => 'tcp',
				       );
    print $as_sock $as;
    print $as_sock "\n";
    
    my $name;
    while (my $as_line = <$as_sock>) {
	if ($as_line =~ /^tun: +(.*)/) {
	    print STDERR "got tun: $1\n";
	    my $tun = $1;
	    
	    my $tun_sock = IO::Socket::INET->new( PeerAddr => '62.169.139.122',
						  PeerPort => 43,
						  Proto    => 'tcp',
						);
	    print $tun_sock $tun;
	    print $tun_sock "\n";
	    
	    my @tun_as;
	    while (my $tun_line = <$tun_sock>) {
		next unless ($tun_line =~ /^as: +(AS\d+)/);
		print STDERR "got as: $1\n";
		my $tun_as = $1;
		push @tun_as, $tun_as;
	    }
	    
	    if (scalar @tun_as == 2) {
		print STDERR "adding tunnel from $tun_as[0] to $tun_as[1]\n";
		$g->add_edge(@tun_as);
	    }
	    
	} elsif ($as_line =~ /^as-name: +(.*)/) {
	    
	    $name = $1;
	    
	}
    }
    $g->add_node($as, label => $name);
    
}

print $g->as_jpeg;

