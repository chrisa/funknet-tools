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

BEGIN { use_ok ( 'Funknet::Config::Host' ); }

# TEST PHASE ONE -- AS64512, an IOS site. 

Funknet::Config::ConfigFile::make_local_sub(as => 'AS64512');

my $host = new Funknet::Config::Host;
my $bgp = $host->sessions;
my $tun = $host->tunnels;

# test BGP object

is (ref $bgp,     'Funknet::Config::BGP::IOS', 'we have a BGP::IOS object');
is ($bgp->source, 'host',                     'source of BGP object is host');

my @neighbors = $bgp->neighbors;
is (scalar @neighbors, 1, 'we have 1 BGP neighbor');
ok (defined $bgp->{_neighbors}->{'10.0.0.2'}, 'it is 10.0.0.2');

my $n = $bgp->{_neighbors}->{'10.0.0.2'};
is (ref $n,          'Funknet::Config::Neighbor', 'we have a Neighbor object');
is ($n->source,      'host',                     'source of Neighbor object is host');
is ($n->remote_addr, '10.0.0.2',                  'peer is 10.0.0.2');
is ($n->remote_as,   '64513',                     'peer AS is AS64513');
is ($n->description, 'SOMETEST-OTHERTEST',        'description is SOMETEST-OTHERTEST');

TODO: {

local $TODO = 'looks like bgp network parsing doesn\'t actually work very well';

is (scalar @{$bgp->routes}, 1,            'we have one BGP network');
is ($bgp->{_routes}->[0],   '1.0.0.0/24', 'it is 1.0.0.0/24');
};

is ($bgp->{_local_as},      '64512',      'our AS is 64512');

# test tunnel object

is (ref $tun,             'Funknet::Config::TunnelSet', 'we have a TunnelSet object');
is ($tun->source,         'host',                      'source of TunnelSet object is host');
is (scalar $tun->tunnels, 1,                            'we have one tunnel');

my $t = $tun->{_tunnels}->[0];
is (ref $t,                 'Funknet::Config::Tunnel::IOS', 'it is an IOS tunnel');
is ($t->{_local_address},   '10.0.0.1',                     'local address is 10.0.0.1');
is ($t->{_remote_address},  '10.0.0.2',                     'remote address is 10.0.0.2');
is ($t->{_local_endpoint},  '1.2.3.4',                      'local endpoint is 1.2.3.4');
is ($t->{_remote_endpoint}, '1.4.3.2',                      'remote endpoint is 1.4.3.2');
is ($t->source,             'host',                        'source of tunnel object is host');
is ($t->type,               'ipip',                         'type of tunnel object is ipip');
is ($t->{_proto},           '4',                            'protocol of tunnel object is IPv4');

# # TEST PHASE ONE -- AS64515, a Zebra/BSD site. 

# Funknet::Config::ConfigFile::make_local_sub( as => 'AS64515',
#                                              os => 'bsd',
# 					     router => 'zebra' );

# my $host = new Funknet::Config::Host;
# my $bgp = $host->sessions;
# my $tun = $host->tunnels;

# # test BGP object

# is (ref $bgp,     'Funknet::Config::BGP::IOS', 'we have a BGP::IOS object');
# is ($bgp->source, 'host',                     'source of BGP object is host');

# my @neighbors = $bgp->neighbors;
# is (scalar @neighbors, 1, 'we have 1 BGP neighbor');
# ok (defined $bgp->{_neighbors}->{'10.0.0.2'}, 'it is 10.0.0.2');

# my $n = $bgp->{_neighbors}->{'10.0.0.2'};
# is (ref $n,          'Funknet::Config::Neighbor', 'we have a Neighbor object');
# is ($n->source,      'host',                     'source of Neighbor object is host');
# is ($n->remote_addr, '10.0.0.2',                  'peer is 10.0.0.2');
# is ($n->remote_as,   '64513',                     'peer AS is AS64513');
# is ($n->description, 'SOMETEST-OTHERTEST',        'description is SOMETEST-OTHERTEST');

# TODO: {

# local $TODO = 'looks like bgp network parsing doesn\'t actually work very well';

# is (scalar @{$bgp->routes}, 1,            'we have one BGP network');
# is ($bgp->{_routes}->[0],   '1.0.0.0/24', 'it is 1.0.0.0/24');
# };

# is ($bgp->{_local_as},      '64512',      'our AS is 64512');

# # test tunnel object

# is (ref $tun,             'Funknet::Config::TunnelSet', 'we have a TunnelSet object');
# is ($tun->source,         'host',                      'source of TunnelSet object is host');
# is (scalar $tun->tunnels, 1,                            'we have one tunnel');

# my $t = $tun->{_tunnels}->[0];
# is (ref $t,                 'Funknet::Config::Tunnel::IOS', 'it is an IOS tunnel');
# is ($t->{_local_address},   '10.0.0.1',                     'local address is 10.0.0.1');
# is ($t->{_remote_address},  '10.0.0.2',                     'remote address is 10.0.0.2');
# is ($t->{_local_endpoint},  '1.2.3.4',                      'local endpoint is 1.2.3.4');
# is ($t->{_remote_endpoint}, '1.4.3.2',                      'remote endpoint is 1.4.3.2');
# is ($t->source,             'host',                        'source of tunnel object is host');
# is ($t->type,               'ipip',                         'type of tunnel object is ipip');
# is ($t->{_proto},           '4',                            'protocol of tunnel object is IPv4');


# ==========================================================================
#
# Fake Net::Telnet implementation

package Net::Telnet;
use strict;

no warnings 'redefine';

sub new {
    my ($class) = @_;
    my $self = bless {}, $class;
    return $self;
}

sub open {
    my ($self, $host) = @_;
    if ($host eq '127.0.0.1') {
	return 1;
    } else {
	return undef;
    }
}

sub cmd {
    my ($self, $cmd) = @_;
    
    if ($cmd eq 'show ip bgp') {
	return split "\n", <<OUTPUT;
BGP table version is 35, local router ID is 213.210.34.174
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal
Origin codes: i - IGP, e - EGP, ? - incomplete

   Network          Next Hop            Metric LocPrf Weight Path
*> 10.2.0.0/24      10.0.0.2                0             0 64513 i
*> 10.6.6.0/24      10.0.0.2                              0 64513 65005 i
*> 10.10.38.0/24    10.0.0.2                              0 64513 65017 i
*> 192.168.9.0      10.0.0.2                              0 64513 65007 i
*> 192.168.20.0     10.0.0.2                              0 64513 65005 i
*> 192.168.24.0     10.0.0.2                              0 64513 65008 i
*> 192.168.30.0     10.0.0.2                              0 64513 65020 i
*> 1.0.0.0/24       0.0.0.0                 1         32768 i
*> 192.168.160.0    10.0.0.2                              0 64513 65004 i
*> 192.168.246.0    10.0.0.2                              0 64513 65008 i
*> 213.210.34.144/28
                    10.0.0.2                              0 64513 65006 i
*> 213.210.34.176/28
                    0.0.0.0                  1         32768 i
nodnol-tun>
OUTPUT

    }

    if ($cmd eq 'show ip bgp sum') {
	return split "\n", <<OUTPUT;
BGP router identifier 213.210.34.174, local AS number 64512
BGP table version is 35, main routing table version 35
13 network entries and 13 paths using 1729 bytes of memory
9 BGP path attribute entries using 540 bytes of memory
8 BGP AS-PATH entries using 192 bytes of memory
0 BGP route-map cache entries using 0 bytes of memory
0 BGP filter-list cache entries using 0 bytes of memory
1 received paths for inbound soft reconfiguration
BGP activity 25/180 prefixes, 30/14 paths, scan interval 60 secs

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2       4 64513    2744    2741       35    0    0 1d21h          10
nodnol-tun>
OUTPUT
}

    if ($cmd eq 'show ip bgp neighbors') {
	return split "\n", <<OUTPUT;
BGP neighbor is 10.0.0.2,  remote AS 64513, external link
 Description: SOMETEST-OTHERTEST
  BGP version 4, remote router ID 131.231.83.95
  BGP state = Established, up for 1d21h
  Last read 00:00:55, hold time is 180, keepalive interval is 60 seconds
  Neighbor capabilities:
    Route refresh: advertised and received(new)
    Address family IPv4 Unicast: advertised and received
    Address family IPv4 Multicast: advertised and received
  Received 2744 messages, 0 notifications, 0 in queue
  Sent 2742 messages, 0 notifications, 0 in queue
  Route refresh request: received 0, sent 0
  Default minimum time between advertisement runs is 30 seconds

 For address family: IPv4 Unicast
  BGP table version 35, neighbor version 35
  Index 1, Offset 0, Mask 0x2
  Inbound soft reconfiguration allowed
  Inbound path policy configured
  Outbound path policy configured
  Route map for incoming advertisements is 64513import
  Route map for outgoing advertisements is 64513export
  10 accepted prefixes consume 360 bytes
  Prefix advertised 2, suppressed 0, withdrawn 0
  1 denied but saved prefixes consume 36 bytes
  Number of NLRIs in the update sent: max 1, min 0

 For address family: IPv4 Multicast
  BGP table version 4, neighbor version 4
  Index 1, Offset 0, Mask 0x2
  1 accepted prefixes consume 36 bytes
  Prefix advertised 2, suppressed 0, withdrawn 0
  Number of NLRIs in the update sent: max 1, min 0

  Connections established 1; dropped 0
  Last reset never
Connection state is ESTAB, I/O status: 1, unread input bytes: 0
Local host: 10.0.0.1, Local port: 179
Foreign host: 10.0.0.2, Foreign port: 3829

Enqueued packets for retransmit: 0, input: 0  mis-ordered: 0 (0 bytes)

Event Timers (current time is 0x9C8BDF4):
Timer          Starts    Wakeups            Next
Retrans          2807         68             0x0
TimeWait            0          0             0x0
AckHold          2736       2677             0x0
SendWnd             0          0             0x0
KeepAlive           0          0             0x0
GiveUp              0          0             0x0
PmtuAger            0          0             0x0
DeadWait            0          0             0x0

iss: 3930011331  snduna: 3930063622  sndnxt: 3930063622     sndwnd:  57600
irs: 3543421881  rcvnxt: 3543474736  rcvwnd:      15605  delrcvwnd:    779

SRTT: 300 ms, RTTO: 303 ms, RTV: 3 ms, KRTT: 0 ms
minRTT: 52 ms, maxRTT: 2124 ms, ACK hold: 200 ms
Flags: passive open, nagle, gen tcbs

Datagrams (max data segment is 1440 bytes):
Rcvd: 5525 (out of order: 0), with data: 2736, total data bytes: 52854
Sent: 5462 (retransmit: 68), with data: 2738, total data bytes: 52290
nodnol-tun>
OUTPUT
}

    if ($cmd =~ /show ip bgp neighbor (\d+\.\d+\.\d+\.\d+)/) {
	return split "\n", <<OUTPUT;
	BGP neighbor is 10.0.0.2,  remote AS 64513, external link
 Description: SOMETEST-OTHERTEST
  BGP version 4, remote router ID 131.231.83.95
  BGP state = Established, up for 1d21h
  Last read 00:00:45, hold time is 180, keepalive interval is 60 seconds
  Neighbor capabilities:
    Route refresh: advertised and received(new)
    Address family IPv4 Unicast: advertised and received
    Address family IPv4 Multicast: advertised and received
  Received 2746 messages, 0 notifications, 0 in queue
  Sent 2744 messages, 0 notifications, 0 in queue
  Route refresh request: received 0, sent 0
  Default minimum time between advertisement runs is 30 seconds

 For address family: IPv4 Unicast
  BGP table version 35, neighbor version 35
  Index 1, Offset 0, Mask 0x2
  Inbound soft reconfiguration allowed
  Inbound path policy configured
  Outbound path policy configured
  Route map for incoming advertisements is 64513import
  Route map for outgoing advertisements is 64513export
  10 accepted prefixes consume 360 bytes
  Prefix advertised 2, suppressed 0, withdrawn 0
  1 denied but saved prefixes consume 36 bytes
  Number of NLRIs in the update sent: max 1, min 0

 For address family: IPv4 Multicast
  BGP table version 4, neighbor version 4
  Index 1, Offset 0, Mask 0x2
  1 accepted prefixes consume 36 bytes
  Prefix advertised 2, suppressed 0, withdrawn 0
  Number of NLRIs in the update sent: max 1, min 0

  Connections established 1; dropped 0
  Last reset never
Connection state is ESTAB, I/O status: 1, unread input bytes: 0
Local host: 10.0.0.1, Local port: 179
Foreign host: 10.0.0.2, Foreign port: 3829

Enqueued packets for retransmit: 0, input: 0  mis-ordered: 0 (0 bytes)

Event Timers (current time is 0x9CA6D68):
Timer          Starts    Wakeups            Next
Retrans          2809         68             0x0
TimeWait            0          0             0x0
AckHold          2738       2679             0x0
SendWnd             0          0             0x0
KeepAlive           0          0             0x0
GiveUp              0          0             0x0
PmtuAger            0          0             0x0
DeadWait            0          0             0x0

iss: 3930011331  snduna: 3930063660  sndnxt: 3930063660     sndwnd:  57600
irs: 3543421881  rcvnxt: 3543474774  rcvwnd:      15567  delrcvwnd:    817

SRTT: 300 ms, RTTO: 303 ms, RTV: 3 ms, KRTT: 0 ms
minRTT: 52 ms, maxRTT: 2124 ms, ACK hold: 200 ms
Flags: passive open, nagle, gen tcbs

Datagrams (max data segment is 1440 bytes):
Rcvd: 5529 (out of order: 0), with data: 2738, total data bytes: 52892
Sent: 5466 (retransmit: 68), with data: 2740, total data bytes: 52328
nodnol-tun>
OUTPUT
}

    if ($cmd =~ /sho ip prefix-list (.*)/) {
	my $pl = $1;
	
	if ($pl eq '64513import') {
	    return split "\n", <<OUTPUT;
ip prefix-list 64513import: 23 entries
   seq 5 permit 10.1.1.0/24
   seq 10 permit 10.2.0.0/24
   seq 15 permit 10.6.6.0/24
   seq 20 permit 10.10.38.0/24
   seq 25 permit 10.34.215.0/24
   seq 30 permit 10.64.160.0/24
   seq 35 permit 192.168.0.0/24
   seq 40 permit 192.168.2.0/24
   seq 45 permit 192.168.9.0/24
   seq 50 permit 192.168.11.0/24
   seq 55 permit 192.168.20.0/24
   seq 60 permit 192.168.24.0/24
   seq 65 permit 192.168.30.0/24
   seq 70 permit 192.168.34.0/24
   seq 75 permit 192.168.110.0/24
   seq 80 permit 192.168.130.0/24
   seq 85 permit 192.168.160.0/24
   seq 90 permit 192.168.246.0/24
   seq 95 permit 213.129.72.1/32
   seq 100 permit 213.210.24.216/29
   seq 105 permit 213.210.34.144/28
   seq 110 permit 213.210.62.192/27
   seq 115 deny 0.0.0.0/0 le 32
nodnol-tun>
OUTPUT
	} elsif ($pl eq '64513export') {
	    return split "\n", <<OUTPUT;
sho ip prefix-list 64513export
ip prefix-list 64513export: 3 entries
   seq 5 permit 192.168.74.0/24
   seq 10 permit 213.210.34.176/28
   seq 15 deny 0.0.0.0/0 le 32
nodnol-tun>
OUTPUT
	} else {
	    return undef;
	}
    }

    if ($cmd eq 'show interfaces') {
	return split "\n", <<OUTPUT;
BRI0 is administratively down, line protocol is down 
  Hardware is BRI
  MTU 1500 bytes, BW 64 Kbit, DLY 20000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation HDLC, loopback not set
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: weighted fair
  Output queue: 0/1000/64/0 (size/max total/threshold/drops) 
     Conversations  0/0/16 (active/max active/max total)
     Reserved Conversations 0/0 (allocated/max allocated)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes, 0 no buffer
     Received 0 broadcasts, 0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort
     0 packets output, 0 bytes, 0 underruns
     0 output errors, 0 collisions, 1 interface resets
     0 output buffer failures, 0 output buffers swapped out
     0 carrier transitions
BRI0:1 is administratively down, line protocol is down 
  Hardware is BRI
  MTU 1500 bytes, BW 64 Kbit, DLY 20000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation HDLC, loopback not set
  Keepalive set (10 sec)
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: weighted fair
  Output queue: 0/1000/64/0 (size/max total/threshold/drops) 
     Conversations  0/0/16 (active/max active/max total)
     Reserved Conversations 0/0 (allocated/max allocated)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes, 0 no buffer
     Received 0 broadcasts, 0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort
     0 packets output, 0 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 output buffer failures, 0 output buffers swapped out
     0 carrier transitions
BRI0:2 is administratively down, line protocol is down 
  Hardware is BRI
  MTU 1500 bytes, BW 64 Kbit, DLY 20000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation HDLC, loopback not set
  Keepalive set (10 sec)
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: weighted fair
  Output queue: 0/1000/64/0 (size/max total/threshold/drops) 
     Conversations  0/0/16 (active/max active/max total)
     Reserved Conversations 0/0 (allocated/max allocated)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes, 0 no buffer
     Received 0 broadcasts, 0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort
     0 packets output, 0 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 output buffer failures, 0 output buffers swapped out
     0 carrier transitions
Dialer0 is up (spoofing), line protocol is up (spoofing)
  Hardware is Unknown
  MTU 1500 bytes, BW 56 Kbit, DLY 20000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation HDLC, loopback not set
  DTR is pulsed for 1 seconds on reset
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: weighted fair
  Output queue: 0/1000/64/0 (size/max total/threshold/drops) 
     Conversations  0/0/16 (active/max active/max total)
     Reserved Conversations 0/0 (allocated/max allocated)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes
     0 packets output, 0 bytes
Dialer1 is up (spoofing), line protocol is up (spoofing)
  Hardware is Unknown
  Internet address will be negotiated using IPCP
  MTU 1500 bytes, BW 56 Kbit, DLY 20000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation HDLC, loopback not set
  DTR is pulsed for 1 seconds on reset
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: weighted fair
  Output queue: 0/1000/64/0 (size/max total/threshold/drops) 
     Conversations  0/0/16 (active/max active/max total)
     Reserved Conversations 0/0 (allocated/max allocated)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes
     0 packets output, 0 bytes
Ethernet0 is up, line protocol is up 
  Hardware is QUICC Ethernet, address is 0050.5498.f438 (bia 0050.5498.f438)
  Internet address is 213.210.34.174/28
  MTU 1500 bytes, BW 10000 Kbit, DLY 1000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:00, output 00:00:00, output hang never
  Last clearing of "show interface" counters never
  Input queue: 2/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue :0/40 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     53852 packets input, 3652237 bytes, 0 no buffer
     Received 7612 broadcasts, 0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 input packets with dribble condition detected
     48744 packets output, 6027828 bytes, 0 underruns
     0 output errors, 17 collisions, 1 interface resets
     0 babbles, 0 late collision, 250 deferred
     0 lost carrier, 0 no carrier
     0 output buffer failures, 0 output buffers swapped out
Serial0 is administratively down, line protocol is down 
  Hardware is QUICC Serial
  MTU 1500 bytes, BW 1544 Kbit, DLY 20000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation HDLC, loopback not set
  Keepalive set (10 sec)
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: weighted fair
  Output queue: 0/1000/64/0 (size/max total/threshold/drops) 
     Conversations  0/0/256 (active/max active/max total)
     Reserved Conversations 0/0 (allocated/max allocated)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes, 0 no buffer
     Received 0 broadcasts, 0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort
     0 packets output, 0 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 output buffer failures, 0 output buffers swapped out
     0 carrier transitions
     DCD=up  DSR=down  DTR=down  RTS=down  CTS=down

Tunnel0 is up, line protocol is up 
  Hardware is Tunnel
  Internet address is 10.0.0.1/30
  MTU 1514 bytes, BW 9 Kbit, DLY 500000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation TUNNEL, loopback not set
  Keepalive not set
  Tunnel source 1.2.3.4 (Ethernet0), destination 1.4.3.2
  Tunnel protocol/transport IP/IP, key disabled, sequencing disabled
  Checksumming of packets disabled,  fast tunneling enabled
  Path MTU Discovery, ager 10 mins, MTU 0, expires never
  Last input 00:00:25, output 00:00:24, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 1
  Queueing strategy: fifo
  Output queue :0/0 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     11516 packets input, 678002 bytes, 0 no buffer
     Received 0 broadcasts, 0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort
     11489 packets output, 838309 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 output buffer failures, 0 output buffers swapped out
Tunnel1 is up, line protocol is up 
  Hardware is Tunnel
  Internet address is 10.2.5.2/30
  MTU 1514 bytes, BW 9 Kbit, DLY 500000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation TUNNEL, loopback not set
  Keepalive not set
  Tunnel source 213.210.34.174, destination 81.98.174.210
  Tunnel protocol/transport IP/IP, key disabled, sequencing disabled
  Checksumming of packets disabled,  fast tunneling enabled
  Last input 00:00:04, output 1d21h, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue :0/0 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     32567 packets input, 2084272 bytes, 0 no buffer
     Received 0 broadcasts, 0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort
     2 packets output, 1248 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 output buffer failures, 0 output buffers swapped out
Tunnel2 is up, line protocol is down 
  Hardware is Tunnel
  MTU 1514 bytes, BW 9 Kbit, DLY 500000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation TUNNEL, loopback not set
  Keepalive not set
  Tunnel source 0.0.0.0, destination 0.0.0.0
  Tunnel protocol/transport GRE/IP, key disabled, sequencing disabled
  Checksumming of packets disabled,  fast tunneling enabled
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue :0/0 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes, 0 no buffer
     Received 0 broadcasts, 0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort
     0 packets output, 0 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 output buffer failures, 0 output buffers swapped out
nodnol-tun>
OUTPUT
}
}

sub getline {}

sub input_log {}

sub close {}

# ==========================================================================
#
# Fake Funknet::Config::ConfigFile implementation.
#
# Just returns a local-foo structure.

package Funknet::Config::ConfigFile;
use strict;

# factory method for a 'local' sub. don't ask. just don't ask. 

sub make_local_sub {
    my (%args) = @_;

    my $local_hash = {
	 as       => $args{as}         || 'AS64514',
	 os       => $args{os}         || 'ios',
	 host     => $args{host}       || '127.0.0.1',
	 router   => $args{router}     || 'ios',
	 endpoint => $args{endpoint}   || '1.2.3.4',
    };

    *local=sub {
        return $local_hash;
    };
}

sub AUTOLOAD {
    return '';
}
