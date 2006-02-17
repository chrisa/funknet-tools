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


package Funknet::Config::Tunnel::Solaris;
use strict;
use base qw/ Funknet::Config::Tunnel /;

=head1 NAME

Funknet::Config::Tunnel::Solaris

=head1 DESCRIPTION

This class contains methods for parsing, creating and deleting tunnel
interfaces on Solaris.

=head1 METHODS

=head2 config

Returns the configuration of the Tunnel object as text. This should be
in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 new_from_ifconfig

Reads a host interface description taken from ifconfig and parses the
useful information from it. Only 'ip.tun' (equivalent to BSD 'gif')
interfaces are supported for Solaris; other interface types cause this
method to return undef.

=head2 create

Returns a list of strings containing commands to configure a tunnel
interface on Solaris. The interface details are passed in as part of
$self, and the new interface number is passed in as $inter. The
commands should assume that no interface with that number currently
exists.

=head2 delete

Returns a list of strings containing commands to unconfigure a tunnel
interface on Solaris. The interface should be removed
(i.e. unplumbed), not just put into the 'down' state.

=cut

sub config {
    my ($self) = @_;

    return 
	"Solaris\n" .
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
	my $tun = Funknet::Config::Tunnel::Solaris->new_from_ifconfig( $if );
	if (defined $tun) {
	    push @local_tun, $tun;
	}
    }
    return @local_tun;
}

sub new_from_ifconfig {
    my ($class, $if) = @_;

    my ($type, $interface, $ifname);
    if ($if =~ /^(ip.tun)(\d+)/) {
	$type = 'ipip';
	$interface = $2;
	$ifname = "$1$2";
    }
    defined $type or return undef;

    my ($local_endpoint, $remote_endpoint) 
	= $if =~ /inet tunnel src (\d+\.\d+\.\d+\.\d+)\s+tunnel dst (\d+\.\d+\.\d+\.\d+)/;
    my ($local_address, $remote_address)
	= $if =~ /inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+)/;

    return Funknet::Config::Tunnel->new(
	name => 'none',
	local_address => $local_address,
	remote_address => $remote_address,
	local_endpoint => $local_endpoint,
	remote_endpoint => $remote_endpoint,
	interface => $interface,
	type => $type,
	source => 'host',
	ifname => $ifname,
	proto => '4',
    );
}

sub delete {
    my ($self) = @_;
    return Funknet::Config::CommandSet->new( cmds => [ "ifconfig ip.tun$self->{_interface} inet unplumb" ],
					     target => 'host',
					   );
}

sub create {
    my ($self, $inter) = @_;

    # stash the interface name this will get in the object
    # (firewall rule gen needs this later)
    $self->{_ifname} = "ip.tun$inter";

    my @cmds = (
		"ifconfig ip.tun$inter inet plumb",
		"ifconfig ip.tun$inter inet tsrc $self->{_local_endpoint} tdst $self->{_remote_endpoint}",
		"ifconfig ip.tun$inter inet $self->{_local_address} $self->{_remote_address} netmask 255.255.255.252 up" );
    return Funknet::Config::CommandSet->new( cmds => \@cmds,
					     target => 'host',
					   );
}

sub ifsym {
    return 'ip.tun';
}

sub valid_type {
    my ($type) = @_;
    $type eq 'ipip' && return 1;
    $type eq 'gre'  && return 1;
    return 0;
}

sub nat_firewall_rules {
    return;
}

sub filter_firewall_rules {
    my ($self) = @_;
    my @rules_out;

    @rules_out = $self->SUPER::firewall_rules();

    my $proto;
    if ($self->{_type} eq 'ipip') { $proto = '4' };
    if ($self->{_type} eq 'gre')  { $proto = 'gre' };

    push (@rules_out,
          Funknet::Config::FirewallRule->new(
                                             proto               => $proto,
                                             source_address      => $self->{_local_endpoint},
                                             destination_address => $self->{_remote_endpoint},
					     direction		 => 'out',
                                             source              => $self->{_source},));

    push (@rules_out,
          Funknet::Config::FirewallRule->new(
                                             proto               => $proto,
                                             source_address      => $self->{_remote_endpoint},
                                             destination_address => $self->{_local_endpoint},
					     direction		 => 'in',
                                             source              => $self->{_source},));

    return (@rules_out);
}

1;
