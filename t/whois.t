#!/usr/local/bin/perl -w
#
# $Id$
#
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
use Test::More tests => 24;

BEGIN { use_ok ( 'Funknet::Config::Whois' ); }

my $whois = new Funknet::Config::Whois;
my $bgp = $whois->sessions;
my $tun = $whois->tunnels;

# test BGP object

is (ref $bgp, 'Funknet::Config::BGP::IOS', 'we have a BGP::IOS object');
is ($bgp->source, 'whois', 'source of BGP object is whois');

my @neighbors = $bgp->neighbors;
is (scalar @neighbors, 1, 'we have 1 BGP neighbor');
ok (defined $bgp->{_neighbors}->{'10.0.0.2'}, 'it is 10.0.0.2');
my $n = $bgp->{_neighbors}->{'10.0.0.2'};
is (ref $n, 'Funknet::Config::Neighbor', 'we have a Neighbor object');
is ($n->source, 'whois', 'source of Neighbor object is whois');
is ($n->remote_addr, '10.0.0.2', 'peer is 10.0.0.2');
is ($n->remote_as, '64513', 'peer AS is AS64513');
is ($n->description, 'SOMETEST-OTHERTEST', 'description is SOMETEST-OTHERTEST');

is (scalar @{$bgp->routes}, 1, 'we have one BGP network');
is ($bgp->{_routes}->[0], '1.0.0.0/24', 'it is 1.0.0.0/24');

is ($bgp->{_local_as}, '64512', 'our AS is 64512');

# test tunnel object

is (ref $tun, 'Funknet::Config::TunnelSet', 'we have a TunnelSet object');
is ($tun->source, 'whois', 'source of TunnelSet object is whois');
is (scalar $tun->tunnels, 1, 'we have one tunnel');
my $t = $tun->{_tunnels}->[0];
is (ref $t, 'Funknet::Config::Tunnel::IOS', 'it is an IOS tunnel');
is ($t->{_local_address}, '10.0.0.1', 'local address is 10.0.0.1');
is ($t->{_remote_address}, '10.0.0.2', 'remote address is 10.0.0.2');
is ($t->{_local_endpoint}, '1.2.3.4', 'local endpoint is 1.2.3.4');
is ($t->{_remote_endpoint}, '1.4.3.2', 'remote endpoint is 1.4.3.2');
is ($t->source, 'whois', 'source of tunnel object is whois');
is ($t->type, 'ipip', 'type of tunnel object is ipip');
is ($t->{_proto}, '4', 'protocol of tunnel object is IPv4');

# ==========================================================================
#
# Fake Net::Whois::RIPE implementation.
# 
# Uses Net::Whois::RIPE::Object still, but uses IO::Scalar to fake
# responses from the whois server. 

package Net::Whois::RIPE;
use strict;
use Net::Whois::RIPE::Object;
use IO::Scalar;

no warnings 'redefine';

sub new {
    my ($class) = @_;
    return bless{}, $class;
}

sub source {}
sub type {
    my ($self, $type) = @_;
    $self->{type} = $type;
}
sub inverse_lookup {
    my ($self, $il) = @_;
    $self->{il} = $il;
}   

sub query {
    my ($self, $q) = @_;

    if ($self->{type} eq 'aut-num') {
	return undef unless $q eq 'AS64512';
	my $object_text = <<OBJ;
aut-num:      AS64512
as-name:      TEST
descr:        testing system
tun:          SOMETEST-OTHERTEST
admin-c:      TEST-FUNKNET
tech-c:       TEST-FUNKNET
mnt-by:       FUNK-MNT
changed:      chris\@nodnol.org 20030719
source:       FUNKNET
OBJ
        my $sh = new IO::Scalar \$object_text;
	my $object = Net::Whois::RIPE::Object->new($sh);
	return $object;
    }

    if ($self->{type} eq 'tunnel') {
	return undef unless $q eq 'SOMETEST-OTHERTEST';
	my $object_text = <<OBJ;
tunnel:       SOMETEST-OTHERTEST
type:         ipip
as:           AS64512
as:           AS64513
address:      10.0.0.1
address:      10.0.0.2
endpoint:     1.2.3.4
endpoint:     1.4.3.2
admin-c:      TEST-FUNKNET
tech-c:       TEST-FUNKNET
mnt-by:       FUNK-MNT
changed:      chris\@nodnol.org 20030719
source:       FUNKNET
OBJ
        my $sh = new IO::Scalar \$object_text;
	my $object = Net::Whois::RIPE::Object->new($sh);
	return $object;
    }
    return undef;
}
   
sub query_iterator {
    my ($self, $q) = @_;
    return undef unless $q eq 'AS64512';
    return undef unless $self->{il} eq 'origin';
    return undef unless $self->{type} eq 'route';

    $self->{iter} = 1;
    return $self;
}

sub next {
    my ($self) = @_;
    return undef if $self->{been_here};
    return undef unless $self->{iter};
    
	my $object_text = <<OBJ;
route:        1.0.0.0/24
descr:        TEST-NETWORK
origin:       AS64512
mnt-by:       FUNK-MNT
changed:      chris\@nodnol.org 20030719
source:       FUNKNET
OBJ
    my $sh = new IO::Scalar \$object_text;
    my $object = Net::Whois::RIPE::Object->new($sh);
    $self->{been_here} = 1;
    return $object;
}
    
	

# ==========================================================================
#
# Fake Funknet::Config::ConfigFile implementation.
#
# Just returns a local-foo structure.

package Funknet::Config::ConfigFile;
use strict;

no warnings 'redefine';

sub local {

    return {
	 as       => 'AS64512',
	 os       => 'ios',
	 host     => '127.0.0.1',
	 router   => 'ios',
	 endpoint => '1.2.3.4',
     };
}

sub AUTOLOAD {
    return '';
}
