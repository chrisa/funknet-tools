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


package Funknet::Config::FirewallRule;
use strict;

use Funknet::Config::Validate qw/ is_ipv4 is_ipv6 is_valid_type 
                                  is_valid_proto is_valid_ifname /;
use Funknet::Config::FirewallRule::IPTables;
use Funknet::Config::FirewallRule::IPFW;

use base qw/ Funknet::Config /;
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallRule

=head1 DESCRIPTION

This is the generic FirewallRule class. It reads the firewall_type parameter
set by higher-level code, and calls the appropriate routines in the
OS-specific classes, returning an object blessed into a specific
class.

=head1 EXTENDING

Adding a new OS' firewall implementation requires the following changes:
extend sub new to read the new firewall_type parameter; likewise the
constructor in Funknet::Config::FirewallRuleSet.
Add a new module Funknet::Config::FirewallRule::NewType.pm and use it in
this module. Add the new firewall's firewall_type flag to
Funknet::Config::Validate.pm. Implement specific methods in NewType.pm. 

=cut

sub new {
    debug("arrived in Config/FirewallRule.pm new");
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    my $l = Funknet::ConfigFile::Tools->local;

    unless (defined $args{source} && 
	    ($args{source} eq 'whois' || $args{source} eq 'host')) {
	$self->warn("firewall_rule: missing or invalid source");
	return undef;
    } else {
	$self->{_source}              = $args{source};
	$self->{_source_address}      = $args{source_address};
	$self->{_destination_address} = $args{destination_address};
	$self->{_source_port}         = $args{source_port};
	$self->{_destination_port}    = $args{destination_port};
	$self->{_proto}               = $args{proto};

	if(defined($args{rule_num})) {
	    $self->{_rule_num} = $args{rule_num};
	}
	debug("in Config/FirewallRule.pm new source = $self->{_source}");
    }

    # support the 'local_source' parameter. if it exists, and is a valid
    # ipv4 address, then replace $self->{_local_endpoint} with it, and 
    # move existing value to $self->{_local_public_endpoint}

    if (exists $l->{source} && 
	defined $l->{source} && 
	is_ipv4($l->{source})) {

	$self->{_local_public_endpoint} = $self->{_local_endpoint};
	$self->{_local_endpoint} = $l->{source};
    }
   
    # rebless to the actual firewall type

    debug("firewall_type in FirewallRule");
    debug("$l->{firewall_type}");
    $l->{firewall_type} eq 'iptables' and
	bless $self, 'Funknet::Config::FirewallRule::IPTables';
    $l->{firewall_type} eq 'ipfw' and
	bless $self, 'Funknet::Config::FirewallRule::IPFW';

    return $self;
}

sub as_hashkey {
    my ($self) = @_;
    
    my $hash =  "$self->{_proto}-" .
		"$self->{_source_address}-$self->{_source_port}-" .
		"$self->{_destination_address}-$self->{_destination_port}-";
    if(defined($self->{_rule_num})) {
            $hash = $hash . $self->{_rule_num};
    }
    return $hash;
}

sub interface {
    my ($self) = @_;
    return $self->{_interface};
}

sub name {
    my ($self) = @_;
    return $self->{_name};
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

sub rule_num {
    my ($self, $new) = @_;
    if(defined ($new)) {
	$self->{_rule_num} = $new;
    }
    return $self->{_rule_num};
}

sub source {
    my ($self) = @_;
    return $self->{_source};
}

sub remote_endpoint {
    my ($self) = @_;
    return $self->{_remote_endpoint};
}

sub local_endpoint {
    my ($self) = @_;
    return $self->{_local_endpoint};
}

1;
