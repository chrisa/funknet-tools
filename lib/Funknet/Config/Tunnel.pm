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


package Funknet::Config::Tunnel;
use strict;

use Funknet::Config::Validate qw/ is_ipv4 is_ipv6 is_valid_type 
                                  is_valid_proto is_valid_ifname /;
use Funknet::Config::Tunnel::BSD;
use Funknet::Config::Tunnel::IOS;
use Funknet::Config::Tunnel::Linux;
use Funknet::Config::Tunnel::Solaris;

use base qw/ Funknet::Config /;

=head1 NAME

Funknet::Config::Tunnel

=head1 DESCRIPTION

This is the generic Tunnel class. It reads the local_os parameter set
by higher-level code, and calls the appropriate routines in the
OS-specific classes, returning an object blessed into a specific
class.

=head1 EXTENDING

Adding a new OS' tunnel implementation requires the following changes:
extend sub new to read the new local_os parameter; likewise
new_from_ifconfig. Add a new module Funknet::Config::Tunnel::NewOS.pm
and use it in this module. Add the new OS' local_os flag to
Funknet::Config::Validate.pm. Implement specific methods in NewOS.pm. 

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    my $l = Funknet::Config::ConfigFile->local;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'host')) {
	$self->warn("tunnel: missing or invalid source");
	return undef;
    } else {
	$self->{_source} = $args{source};
    }

    if ($self->{_source} eq 'host') {

	# is this an interface we should be ignoring?
	my @ignore_if = Funknet::Config::ConfigFile->ignore_if;
	if (defined $args{ifname} && (grep /$args{ifname}/, @ignore_if)) {
	    $self->warn("ignoring $args{ifname}");
	    return undef;
	}
	
	if (defined $args{interface}) {
	    $self->{_interface} = $args{interface};
	} else {
	    $self->warn("$args{ifname}: missing interface for host tunnel");
	}
	unless (defined $args{ifname} && is_valid_ifname($args{ifname})) {
	    $self->warn("missing or invalid ifname: $args{ifname}");
	    return undef;
	} else {
	    $self->{_ifname} = $args{ifname};
	}
    }    

    unless (defined $args{type} && is_valid_type($args{type})) {
	$self->warn("$args{ifname}: missing or invalid type");
	return undef;
    } else {
	$self->{_type} = $args{type};
    }

    unless (defined $args{proto} && is_valid_proto($args{proto})) {
	$self->warn("$args{ifname}: missing or invalid protocol");
	return undef;
    } else {
	$self->{_proto} = $args{proto};
    }
    
    if ($self->{_proto} eq '4') {
	for my $addr (qw/ local_address remote_address local_endpoint remote_endpoint / ) {
	    unless (is_ipv4 ($args{$addr})) {
		$self->warn("$args{ifname} $addr: missing or invalid ipv4 address");
		return undef;
	    } else {
		$self->{"_$addr"} = $args{$addr};
	    }
	} 
    } elsif ($self->{_proto} eq '6') {
	for my $addr (qw/ local_address remote_address / ) {
	    unless (is_ipv6 ($args{$addr})) {
		$self->warn("$args{ifname} $addr: invalid ipv6 address");
		return undef;
	    } else {
		$self->{"_$addr"} = $args{$addr};
	    }
	}
	for my $addr (qw/ local_endpoint remote_endpoint / ) {
	    unless (is_ipv4 ($args{$addr})) {
		$self->warn("$args{ifname} $addr: invalid ipv4 address");
		return undef;
	    } else {
		$self->{"_$addr"} = $args{$addr};
	    }
	}
    }
    if ($self->{_source} eq 'host') {
    }
	 
    # support the 'local_source' parameter. if it exists, and is a valid
    # ipv4 address, then replace $self->{_local_endpoint} with it, and 
    # move existing value to $self->{_local_public_endpoint}

    if (exists $l->{source} && defined $l->{source} && is_ipv4($l->{source})) {
	$self->{_local_public_endpoint} = $self->{_local_endpoint};
	$self->{_local_endpoint} = $l->{source};
    }
   
    # rebless if we have a specific OS to target 
    # for this tunnel endpoint.

    $l->{os} eq 'bsd' and 
	bless $self, 'Funknet::Config::Tunnel::BSD';
    $l->{os} eq 'ios' and 
	bless $self, 'Funknet::Config::Tunnel::IOS';
    $l->{os} eq 'linux' and
	bless $self, 'Funknet::Config::Tunnel::Linux';
    $l->{os} eq 'solaris' and
	bless $self, 'Funknet::Config::Tunnel::Solaris';

    return $self;
}

sub as_string {
    my ($self) = @_;
    
    return 
	"$self->{_type}:\n" .
	"$self->{_local_endpoint} -> $self->{_remote_endpoint}\n" . 
	"$self->{_local_address} -> $self->{_remote_address}\n";
}

sub as_hashkey {
    my ($self) = @_;
    
    return 
	"$self->{_type}-" .
	"$self->{_local_endpoint}-$self->{_remote_endpoint}-" . 
	"$self->{_local_address}-$self->{_remote_address}";
}

sub new_from_ifconfig {
    my ($class, $if) = @_;
    my $l = Funknet::Config::ConfigFile->local;
    
    if ($l->{os} eq 'bsd') {
	return Funknet::Config::Tunnel::BSD->new_from_ifconfig( $if );
    }
    if ($l->{os} eq 'linux') {
	return Funknet::Config::Tunnel::Linux->new_from_ifconfig( $if );
    }
    if ($l->{os} eq 'solaris') {
	return Funknet::Config::Tunnel::Solaris->new_from_ifconfig( $if );
    }
    return undef;
}

sub interface {
    my ($self) = @_;
    return $self->{_interface};
}

sub type {
    my ($self) = @_;
    return $self->{_type};
}

sub local_os {
    my ($self) = @_;
    return $self->{_local_os};
}

sub ifname {
    my ($self) = @_;
    return $self->{_ifname};
}
sub source {
    my ($self) = @_;
    return $self->{_source};
}
1;
