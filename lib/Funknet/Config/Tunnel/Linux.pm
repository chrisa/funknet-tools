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


package Funknet::Config::Tunnel::Linux;
use strict;
use base qw/ Funknet::Config::Tunnel /;

=head1 NAME

Funknet::Config::Tunnel::Linux

=head1 DESCRIPTION

This class contains methods for parsing, creating and deleting tunnel
interfaces on Linux.

=head1 METHODS

=head2 config

Returns the configuration of the Tunnel object as text. This should be
in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 new_from_ifconfig

Reads a host interface description taken from ifconfig and parses the
useful information from it. IPIP and GRE interfaces are supported for
Linux; other interface types cause this method to return
undef. Interface naming under Linux: interfaces need to be numbered,
and the create, delete and new_from_ifconfig methods need to agree on
the names.

=head2 create

Returns a list of strings containing commands to configure a tunnel
interface on Linux. The interface details are passed in as part of
$self, and the new interface number is passed in as $inter. The
commands should assume that no interface with that number currently
exists.

=head2 delete

Returns a list of strings containing commands to unconfigure a tunnel
interface on Linux. The interface should be removed, not just put into
the 'down' state.

=cut

sub config {
    my ($self) = @_;

    return 
	"Linux\n" .
	"$self->{_type}:\n" .
	"$self->{_local_endpoint} -> $self->{_remote_endpoint}\n" . 
	"$self->{_local_address} -> $self->{_remote_address}\n";
}

sub new_from_ifconfig {
    my ($class, $if) = @_;

# this needs writing for linux - this code was pinched from BSD.pm

#     my $type;
#     $if =~ /(^gif\d+)/ && $type = 'ipip';
#     $if =~ /(^gre\d+)/ && $type = 'gre';
#     my $interface = $1;
#     defined $type or return undef;

#     my ($local_endpoint, $remote_endpoint) = $if =~ /tunnel inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+)/;
#     my ($local_address, $remote_address)   = $if =~ /inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+) netmask/;

#     return Funknet::Config::Tunnel->new(
# 	name => 'none',
# 	local_address => $local_address,
# 	remote_address => $remote_address,
# 	local_endpoint => $local_endpoint,
# 	remote_endpoint => $remote_endpoint,
# 	type => $type,
# 	source => 'host',
#       proto => '4',
#     );
    return undef;
}


sub delete {
    my ($self) = @_;
    return "a list of commands to delete $self->{_interface} on Linux go here";
}

sub create {
    my ($self, $inter) = @_;
    # details are in $self, see Solaris.pm
    return "a list of commands to create a tunnel interface numbered $inter on Linux go here";
}

1;
