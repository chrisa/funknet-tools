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


package Funknet::Config::FirewallRule::IPTables;
use strict;
use base qw/ Funknet::Config::FirewallRule /;
use Funknet::ConfigFile::Tools;
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallRule::IPTables

=head1 DESCRIPTION

This class contains methods for creating and deleting rules in IPTables

=head1 METHODS

=head2 create

Returns a list of strings containing commands to configure a single
IPTables rule, in a chain with the same as the whois_source name.
The required rule details are passed in as part of $self.

=head2 delete

Returns a list of strings containing commands to delete an IPTables
rule from the chain named the same as the whois_source name.

=cut

sub create {
    my ($self) = @_;
    return $self->_iptables_cmd('-A');
}

sub delete {
    my ($self) = @_;
    return $self->_iptables_cmd('-D');
}

sub _iptables_cmd {
    my ($self, $action) = @_;

    my $whois_source = Funknet::ConfigFile::Tools->whois_source || 'FUNKNET';
    my $port_str     = _ports($self);
    my $src_str      = _src($self);
    my $dst_str      = _dst($self);
    my $proto_str    = _proto($self);
    my $inter_str    = _inter($self);
    my $table_str    = _table($self);
    my $j_str        = _j($self);

    return ("iptables $action $whois_source".$table_str.$inter_str.$proto_str.$src_str.$dst_str.$port_str.$j_str);
}

sub create_chain {
    my ($class, $chain) = @_;

    return("iptables -N $chain");
}

sub _ports {
    my ($self) = @_;
    
    my $port_str = " ";
    if (defined $self->{_source_port}) {
	$port_str .= "--sport $self->{_source_port} ";
    }
    if (defined $self->{_destination_port}) {
	$port_str .= "--dport $self->{_destination_port} ";
    }
    return $port_str;
}

sub _src {
    my ($self) = @_;
    
    my $src_str = " ";
    if (defined $self->{_source_address} &&
	$self->{_source_address} ne '0.0.0.0') {
	$src_str .= "-s $self->{_source_address} ";
    }
    return $src_str;
}

sub _dst {
    my ($self) = @_;
    
    my $dst_str = " ";
    if (defined $self->{_destination_address} && 
	$self->{_destination_address} ne '0.0.0.0') {
	$dst_str .= "-d $self->{_destination_address} ";
    }
    return $dst_str;
}

sub _proto {
    my ($self) = @_;
    
    my $proto_str = " ";
    if (defined $self->{_proto} &&
       $self->{_proto} ne 'all') {
	$proto_str .= "-p $self->{_proto} ";
    }
    return $proto_str;
}

sub _inter {
    my ($self) = @_;
    
    my $inter_str = " ";
    if (defined $self->{_in_interface}) {
	$inter_str .= "-i $self->{_in_interface} ";
    }
    if (defined $self->{_out_interface}) {
	$inter_str .= "-o $self->{_out_interface} ";
    }
    return $inter_str;
}

sub _table {
     my ($self) = @_;
     
     my $table_str = " ";
     if (defined $self->{_type}) {
          if ($self->{_type} eq 'filter') {
               $table_str .= '-t filter ';
          }
          if ($self->{_type} eq 'nat') {
               $table_str .= '-t nat ';
          }
     }
     return $table_str;
}

sub _j {
     my ($self) = @_;
     
     my $j_str = " ";
     if ($self->{_type} eq 'nat' && defined $self->{_to_port}) {
          $j_str .= "-j DNAT --to $self->{_to_addr}:$self->{_to_port}";
     }
     if ($self->{_type} eq 'filter') {
          $j_str .= "-j ACCEPT ";
     }
     return $j_str;
}
          

1;
