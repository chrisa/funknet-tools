# Copyright (c) 2006
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


package Funknet::Config::FirewallRule::PF;
use strict;
use base qw/ Funknet::Config::FirewallRule /;
use Funknet::ConfigFile::Tools;
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallRule::PF

=head1 DESCRIPTION

This class contains methods for creating and deleting rules for PF-based
firewalls

PF uses anchors where IPTables uses chains - for named sets of rules that
can be adjusted at runtime. The static pf config must reference these by
name, eg:

 C<nat-anchor FUNKNET-nat>
 C<rdr-anchor FUNKNET-rdr>
 C<anchor FUNKNET>

I'm unsure at the moment if all three anchors are required, or if nat/rdr
rules can go in the filter anchor. For now they're separate.

=head1 METHODS

=head2 create

Returns a list of strings containing commands to configure a single
PF anchor in a chain with the same as the whois_source name.
The required rule details are passed in as part of $self.

=head2 delete

NOP. FLushing entire anchor handled by F::C::FirewallChain::PF::flush

=cut

sub create {
    my ($self) = @_;
    return $self->_pf_cmd();
}

sub delete {
    my ($self) = @_;
    warn "pf doesn't support rule removal";
    return;
}

sub _pf_cmd {
    my ($self) = @_;

    return $self->_command();
}

sub _command {
    my ($self) = @_;
    if (!defined $self) { die 'bad args to _command'; }

    my $cmd = " ";
    if (defined $self->{_type}) {
	if ($self->{_type} eq 'nat') {
	    # pf.conf(5) reckons we don't need interface spec, and we don't
	    # know the real if name anyway
	    $cmd = "rdr ".$self->_proto()." ".$self->_src()." ".$self->_dst().
		   " -> ".
		       (defined $self->{_destination_address} ? "$self->{_destination_address} " : '').
		       (defined $self->{_to_port} ? "port $self->{_to_port} " : '');
	}
	elsif ($self->{_type} eq 'rdr') {
	    die "use a NAT rule to achieve PF rdr rules";
	}
	else {
	    # filter rule
	    if (defined $self->{_out_interface}) {
		$cmd = "pass out on $self->{_out_interface} ".
		       $self->_proto()." ".$self->_src()." ".$self->_dst();
	    }
	    elsif (defined $self->{_in_interface}) {
		$cmd = "pass in on $self->{_in_interface} ".
		       $self->_proto()." ".$self->_src()." ".$self->_dst();
	    }
	    else {
		warn "filter rule without either inside or oustide interface";
		$cmd = "pass ".
		       $self->_proto()." ".$self->_src()." ".$self->_dst();
	    }
	} # nat/rdr/filter
    }
    else {
	die "unknown rule type $self->{_type}";
    }
    return $cmd;
}

# bundle src addr & port
sub _src {
    my ($self) = @_;
    return "from ".
       (defined $self->{_source_address} ?
	"$self->{_source_address}" : "any").
       (defined $self->{_source_port} ?
        " port $self->{_source_port}" : '');
}

# bundle dst addr & port
sub _dst {
    my ($self) = @_;
    return "to ".
       (defined $self->{_destination_address} ?
	"$self->{_destination_address}" : "any").
       (defined $self->{_destination_port} ?
        " port $self->{_destination_port}" : '');
}

sub _proto {
    my ($self) = @_;
    return(defined $self->{_proto} &&
           $self->{_proto} ne 'all' ? "proto $self->{_proto}" : '');
}

1;
