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


package Funknet::Config::FirewallRule::IPF;
use strict;
use base qw/ Funknet::Config::FirewallRule /;
use Funknet::ConfigFile::Tools;
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallRule::IPF

=head1 DESCRIPTION

=head1 METHODS

=head2 create

=head2 delete

=cut

sub create {
    my ($self) = @_;
    return $self->_ipf_cmd;
}

#sub delete {
#    my ($self) = @_;
#    warn "pf doesn't support rule removal";
#    return;
#}

sub _ipf_cmd {
    my ($self) = @_;

    my $group		= Funknet::ConfigFile::Tools->ipf_group_number;
    my $src_str		= $self->_src;
    my $dst_str		= $self->_dst;
    my ($int_str)	= $self->_int;
    my $dir		= $self->direction;
    my $proto_str	= $self->_proto;

    unless (defined ($dir)) {
	warn "ipf rules require a direction";
	return;
    }
    return "pass $dir quick $int_str $proto_str from $src_str to $dst_str group $group";
}

sub _int {
    my ($self) = @_;

    my $int_str = 'on ';

    if (defined ($self->{_in_interface})) {
	$int_str .= $self->{_in_interface};
    } elsif (defined ($self->{_out_interface})) {
	$int_str .= $self->{_out_interface};
    } else {
	$int_str = '';
    }
    return($int_str);
}

sub _proto {
    my ($self) = @_;

    my $proto_str='';

    if (defined ($self->{_proto})) {
	if ($self->{_proto} ne 'all') {
	    $proto_str .= "proto $self->{_proto}";
	}
    }
    return($proto_str);
}
	
#sub _anchor {
#    my ($self) = @_;
#    if (!defined $self) { die 'bad args to _anchor'; }
#
#    my $base = Funknet::ConfigFile::Tools->whois_source || 'FUNKNET';
#    my $suffix;
#    if (defined $self->{_type}) {
#	if ($self->{_type} eq 'nat') {
#	    $suffix="-nat";
#	}
#	elsif ($self->{_type} eq 'rdr') {
#	    $suffix="-rdr";
#	}
#    }
#    return $base.$suffix;
#}
#
## build the command and the interface spec in one, so we can check for nat
## XXX currently unsure how nat/rdr is to be used, so we just die
#sub _command {
#    my ($self) = @_;
#    if (!defined $self) { die 'bad args to _command'; }
#
#    my $cmd = " ";
#    if (defined $self->{_type}) {
#	if ($self->{_type} eq 'nat') {
#	    if (!defined $self->{_out_interface}) {
#		die "nat rule without outside interface";
#	    }
#	    $cmd = "nat on $self->{_out_interface} ";
#	    die "nat rule not ready yet!";
#	}
#	elsif ($self->{_type} eq 'rdr') {
#	    if (!defined $self->{_out_interface}) {
#		die "rdr rule without outside interface";
#	    }
#	    $cmd = "rdr on $self->{_out_interface} ";
#	    die "rdr rule not ready yet!";
#	}
#	else {
#	    # filter rule
#	    if (defined $self->{_out_interface}) {
#		$cmd = "pass out on $self->{_out_interface} ";
#	    }
#	    elsif (defined $self->{_in_interface}) {
#		$cmd = "pass in on $self->{_in_interface} ";
#	    }
#	    else {
#		warn "filter rule without either inside or oustide interface";
#		$cmd = "pass ";
#	    }
#	} # nat/rdr/filter
#    }
#    else {
#	die "unknown rule type $self->{_type}";
#    }
#}

# bundle src addr & port
sub _src {
    my ($self) = @_;
    debug("in IPF _src");
    print Dumper $self;
    
    my $src_str = " ";
    if (defined $self->{_source_address} &&
    $self->{_source_address} ne '0.0.0.0') {
        $src_str .= "$self->{_source_address} ";
    } else {
	$src_str .= "any ";
    }
    if (defined $self->{_source_port}) {
	$src_str .= "port = $self->{_source_port} ";
    }
    return $src_str;
}

# bundle dst addr & port
sub _dst {
    my ($self) = @_;
    
    debug("in IPF _dst");
    print Dumper $self;
    my $dst_str = " ";
    if (defined $self->{_destination_address} && 
    $self->{_destination_address} ne '0.0.0.0') {
	$dst_str .= "$self->{_destination_address} ";
    } else {
	$dst_str .= "any ";
    }
    if (defined $self->{_destination_port}) {
	$dst_str .= "port = $self->{_destination_port} ";
    }
    return $dst_str;
}

1;
