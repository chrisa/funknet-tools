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


package Funknet::Config::Tunnel::BSD;
use strict;
use base qw/ Funknet::Config::Tunnel /;

=head1 NAME

Funknet::Config::Tunnel::BSD

=head1 DESCRIPTION

This class contains methods for parsing, creating and deleting tunnel
interfaces on BSD. (BSD for these purposes includes Free, Net and
OpenBSD, plus Mac OSX). 

=head1 METHODS

=head2 config

Returns the configuration of the Tunnel object as text. This should be
in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 new_from_ifconfig

Reads a host interface description taken from ifconfig and parses the
useful information from it. Only 'gif' and 'gre' interfaces are
supported for BSD; other interface types cause this method to return
undef.

=head2 create

Returns a list of strings containing commands to configure a tunnel
interface on BSD. The interface details are passed in as part of
$self, and the new interface number is passed in as $inter. The
commands should assume that no interface with that number currently
exists.

=head2 delete

Returns a list of strings containing commands to unconfigure a tunnel
interface on BSD. The interface should be removed, not just put into
the 'down' state. 

=cut

sub config {
    my ($self) = @_;

    return 
	"BSD\n" .
	"$self->{_type}:\n" .
	"$self->{_local_endpoint} -> $self->{_remote_endpoint}\n" . 
	"$self->{_local_address} -> $self->{_remote_address}\n";
}

sub host_tunnels {
    my ($class) = @_;
    my @local_tun;
    
    my $c = `/sbin/ifconfig -a`;
    my @if = split /(?=^[a-z])/m,$c;
    
    for my $if (@if) {
	chomp $if;
	my $tun = Funknet::Config::Tunnel::BSD->new_from_ifconfig( $if );
	if (defined $tun) {
	    push @local_tun, $tun;
	}
    }
    return @local_tun;
}

sub new_from_ifconfig {
    my ($class, $if) = @_;

    my ($type, $interface, $ifname);
    if ( $if =~ /^(gif)(\d+)/)
    {
	$type = 'ipip';
	$interface = $2;
	$ifname = "$1$2";
    }
    if ( $if =~ /^(gre)(\d+)/)
    {
	$type = 'gre';
	$interface = $2;
	$ifname = "$1$2";
    }
	
    defined $type or return undef;

    my ($local_endpoint, $remote_endpoint) = $if =~ /tunnel inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+)/;
    my ($local_address, $remote_address)   = $if =~ /inet (\d+\.\d+\.\d+\.\d+) -+> (\d+\.\d+\.\d+\.\d+) netmask/;

    return Funknet::Config::Tunnel->new(
	name => 'none',
	local_address => $local_address,
	remote_address => $remote_address,
	local_endpoint => $local_endpoint,
	remote_endpoint => $remote_endpoint,
	interface => $interface,
	type => $type,
	ifname => $ifname,
	source => 'host',
	proto => '4',
    );
}

sub delete {
    my ($self) = @_;

    my $tun_type;
    for ($self->{_type})
    {
	if    (/ipip/) {$tun_type = 'gif';}
	elsif (/gre/) {$tun_type = 'gre';}
    }

    return Funknet::Config::CommandSet->new( cmds => [ "ifconfig $tun_type$self->{_interface} destroy" ],
					     target => 'host',
					   );
}

sub create {
    my ($self, $inter) = @_;

    my $tun_type;
    for ($self->{_type})
    {
	if    (/ipip/) {$tun_type = 'gif';}
	elsif (/gre/) {$tun_type = 'gre';}
    }

    # stash the interface name this will get in the object
    # (firewall rule gen needs this later)
    $self->{_ifname} = "$tun_type$inter";
    
    my @cmds = 	( "ifconfig $tun_type$inter create mtu 1480",
		  "ifconfig $tun_type$inter tunnel $self->{_local_endpoint} $self->{_remote_endpoint}",
		  "ifconfig $tun_type$inter inet $self->{_local_address} $self->{_remote_address} netmask 255.255.255.252"
		);
    
    return Funknet::Config::CommandSet->new( cmds => \@cmds,
					     target => 'host',
					   );
}

sub ifsym {
    return 'gif';
}

sub valid_type {
    my ($type) = @_;
    $type eq 'ipip' && return 1;
    $type eq 'gre'  && return 1;
    return 0;
}

sub firewall_rules {
    my ($self) = @_;
    my @rules_out;

    @rules_out = $self->SUPER::firewall_rules();
    
    my $proto;
    if ($self->{_type} eq 'ipip') { $proto = 'ipencap' };
    if ($self->{_type} eq 'gre')  { $proto = 'gre' };
    
    push (@rules_out, 
	  Funknet::Config::FirewallRule->new(
					     proto               => $proto,
					     source_address      => $self->{_local_endpoint},
					     destination_address => $self->{_remote_endpoint},
					     source              => $self->{_source},));
    
    push (@rules_out, 
	  Funknet::Config::FirewallRule->new(
					     proto               => $proto,
					     source_address      => $self->{_remote_endpoint},
					     destination_address => $self->{_local_endpoint},
					     source              => $self->{_source},));
    
    return (@rules_out);
}

1;
