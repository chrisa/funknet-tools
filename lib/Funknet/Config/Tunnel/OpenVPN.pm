# Copyright (c) 2005
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


package Funknet::Config::Tunnel::OpenVPN;
use strict;
use base qw/ Funknet::Config::Tunnel /;
use Funknet::Config::Util qw/ dq_to_int /;
use Funknet::Config::SystemFile;

=head1 NAME

Funknet::Config::Tunnel::OpenVPN

=head1 DESCRIPTION

This class contains methods for parsing, creating and deleting tunnel
interfaces on OpenVPN.

=head1 METHODS

=head2 config

Returns the configuration of the Tunnel object as text. This should be
in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 new_from_ifconfig

Reads a host interface description taken from ifconfig and parses the
useful information from it. Only 'tun' and 'tap' interfaces are
supported for OpenVPN; other interface types cause this method to return
undef.

=head2 create

Returns a list of strings containing commands to configure a tunnel
interface with OpenVPN. The interface details are passed in as part of
$self, and the new interface number is passed in as $inter. The
commands should assume that no interface with that number currently
exists.

=head2 delete

Returns a list of strings containing commands to unconfigure an OpenVPN
tunnel interface. The interface should be removed, not just put into
the 'down' state. 

=cut

sub config {
    my ($self) = @_;

    return 
	"OpenVPN\n" .
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
	my $tun = Funknet::Config::Tunnel::OpenVPN->new_from_ifconfig( $if );
	if (defined $tun) {
	    push @local_tun, $tun;
	}
    }
    return @local_tun;
}

sub new_from_ifconfig {
    my ($class, $if) = @_;

    my ($type, $interface, $ifname);
    if ( $if =~ /^(tun)(\d+)/)
    {
	$type = 'tun';
	$interface = $2;
	$ifname = "$1$2";
    }
    if ( $if =~ /^(tap)(\d+)/)
    {
	$type = 'tap';
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

    # generate a filename for our config file (from the whois)
    $self->{_ovpn_file} = '/etc/openvpn/' . $self->{_name} . '.conf';

    # create a SystemFile object on that path
    my $ovpn_file = Funknet::Config::SystemFile->new( text => undef,
						      path => $self->{_ovpn_file} );
    
    return $ovpn_file->delete;
}

sub create {
    my ($self, $inter) = @_;

    # stash the if-index
    $self->{_ovpn_inter} = $inter;
    
    # we only support OpenVPN over tuns, not tap. 
    #if ($self->{_type} eq 'openvpn') {
	$self->{_ovpn_type} = 'tun';
    #}
    
    # stash the interface number this will get in the object
    # (firewall rule gen needs this later)
    $self->{_ifname} = "$self->{_ovpn_type}$inter";

    # decide if we're going to be client or server.
    # (ignoring NAT/dynamic issues here)
    # 
    # lower endpoint ip address gets to be server. 
    #
    if (dq_to_int($self->{_local_endpoint}) < dq_to_int($self->{_remote_endpoint})) {
	$self->{_ovpn_server}++;
    } else {
	$self->{_ovpn_client}++;
    }
    
    # allocate a port
    # here we use 5000+ifindex
    $self->{_ovpn_port} = 5000 + $self->{_ovpn_inter};
    
    # generate a filename for our config file (from the whois)
    $self->{_ovpn_file} = '/etc/openvpn/' . $self->{_name} . '.conf';    
    
    # get our config text
    my $ovpn_conf = _gen_openvpn_conf($self);
 
    my $ovpn_file = Funknet::Config::SystemFile->new( text => $ovpn_conf,
						      path => $self->{_ovpn_file} );
						      
    return $ovpn_file;
}

sub enc_data {
    my ($self, $enc_data) = @_;
    $self->{_ovpn_cert} = $enc_data->{certfile_path};
    $self->{_ovpn_key}  = $enc_data->{keyfile_path};
}

sub ifsym {
    return 'tun';
}

sub valid_type {
    my ($type) = @_;
    $type eq 'tun' && return 1;
    $type eq 'tap' && return 1;
    return 0;
}

sub firewall_rules {
    my ($self) = @_;
    my @rules_out;

    @rules_out = $self->SUPER::firewall_rules();
    
    push (@rules_out, 
	  Funknet::Config::FirewallRule->new(
					     proto               => 'udp',
					     source_address      => $self->{_local_endpoint},
					     destination_address => $self->{_remote_endpoint},
					     source_port         => $self->{_ovpn_port},
					     destination_port    => $self->{_ovpn_port},
					     source              => $self->{_source},));
    
    push (@rules_out, 
	  Funknet::Config::FirewallRule->new(
					     proto               => 'udp',
					     source_address      => $self->{_remote_endpoint},
					     destination_address => $self->{_local_endpoint},
					     source_port         => $self->{_ovpn_port},
					     destination_port    => $self->{_ovpn_port},
					     source              => $self->{_source},));
    
    return (@rules_out);
}

sub tunnel_opvn_file {
    my ($self) = @_;
    return $self->{_ovpn_file};
}    

sub _gen_openvpn_conf {
    my ($self) = @_;
    my $config;

    if ($self->{_ovpn_client}) {

	$config = <<"CLIENTCONFIG";
# autogenerated openvpn.conf
# tunnel $self->{_name}
# from $self->{_local_endpoint} to $self->{_remote_endpoint}
#
# we are client.
#
dev            $self->{_ovpn_type}$self->{_ovpn_inter}
remote         $self->{_remote_endpoint}
ifconfig       $self->{_local_address} $self->{_remote_address}
user           nobody  
group          nobody
port           $self->{_ovpn_port}
tls-client
ca             $self->{_ovpn_ca}
tls-cipher     DHE-RSA-AES256-SHA
replay-persist replay.store.$self->{_ovpn_port}
cert           $self->{_ovpn_cert}
key            $self->{_ovpn_key}
ping           15
verb           5
writepid       /var/run/openvpn.pid.$self->{_ovpn_port}
CLIENTCONFIG
    
    } elsif ($self->{_ovpn_server}) {

	$config = <<"SERVERCONFIG";
# autogenerated openvpn.conf
# tunnel $self->{_name}
# from $self->{_local_endpoint} to $self->{_remote_endpoint}
#
# we are server.
#
dev            $self->{_ovpn_type}$self->{_ovpn_inter}
local          $self->{_local_endpoint}
ifconfig       $self->{_local_address} $self->{_remote_address}
user           nobody  
group          nobody
port           $self->{_ovpn_port}
tls-server
ca             $self->{_ovpn_ca}
dh             dh1024.pem
tls-cipher     DHE-RSA-AES256-SHA
replay-persist replay.store.$self->{_ovpn_port}
cert           $self->{_ovpn_cert}
key            $self->{_ovpn_key}
ping           15
verb           5
writepid       /var/run/openvpn.pid.$self->{_ovpn_port}
SERVERCONFIG
    }
    return $config;
}

sub _parse_openvpn_conf {
    my ($text) = @_;

    my $config;
    for my $line ( split /\n/, $text) {
	
	# skip blank lines; comments
	next unless $line;
	next if $line =~ /^#/;

	my ($key, $val) = $line =~ m!^(\w+)\s+(.*)$!;
	next unless ($key);
	
	$config->{$key} = $val;
    }
    
    return $config;
}

1;
