#!/usr/local/bin/perl -w
use strict;
use Test::More tests => 24;
use Data::Dumper;

BEGIN { use_ok ( 'Funknet::Config::Whois' ); }

my $whois = new Funknet::Config::Whois;
my $bgp = $whois->sessions;
my $tun = $whois->tunnels;

# test BGP object

is (ref $bgp, 'Funknet::Config::BGP::IOS', 'we have a BGP::IOS object');
is ($bgp->{_source}, 'whois', 'source of BGP object is whois');

is (scalar keys %{$bgp->{_neighbors}}, 1, 'we have 1 BGP neighbor');
ok (defined $bgp->{_neighbors}->{'10.0.0.2'}, 'it is 10.0.0.2');
my $n = $bgp->{_neighbors}->{'10.0.0.2'};
is (ref $n, 'Funknet::Config::Neighbor', 'we have a Neighbor object');
is ($n->{_source}, 'whois', 'source of Neighbor object is whois');
is ($n->{_remote_addr}, '10.0.0.2', 'peer is 10.0.0.2');
is ($n->{_remote_as}, '64513', 'peer AS is AS64513');
is ($n->{_description}, 'SOMETEST-OTHERTEST', 'description is SOMETEST-OTHERTEST');

is (scalar @{$bgp->{_routes}}, 1, 'we have one BGP network');
is ($bgp->{_routes}->[0], '1.0.0.0/24', 'it is 1.0.0.0/24');

is ($bgp->{_local_as}, '64512', 'our AS is 64512');

# test tunnel object

is (ref $tun, 'Funknet::Config::TunnelSet', 'we have a TunnelSet object');
is ($tun->{_source}, 'whois', 'source of TunnelSet object is whois');
is (scalar(@{$tun->{_tunnels}}), 1, 'we have one tunnel');
my $t = $tun->{_tunnels}->[0];
is (ref $t, 'Funknet::Config::Tunnel::IOS', 'it is an IOS tunnel');
is ($t->{_local_address}, '10.0.0.1', 'local address is 10.0.0.1');
is ($t->{_remote_address}, '10.0.0.2', 'remote address is 10.0.0.2');
is ($t->{_local_endpoint}, '1.2.3.4', 'local endpoint is 1.2.3.4');
is ($t->{_remote_endpoint}, '1.4.3.2', 'remote endpoint is 1.4.3.2');
is ($t->{_source}, 'whois', 'source of tunnel object is whois');
is ($t->{_type}, 'ipip', 'type of tunnel object is ipip');
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
