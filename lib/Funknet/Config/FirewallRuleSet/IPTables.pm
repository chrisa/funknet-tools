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


package Funknet::Config::FirewallRuleSet::IPTables;
use strict;
use base qw/ Funknet::Config::FirewallRuleSet /;
use Funknet::Debug;

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

sub new {
    my ($class, %args) = @_;
    debug("arrived in IPTables.pm new");
    my $self = bless {}, $class;

    $self->{_source} = $args{source};
    $self->{_firewall} = $args{firewall};

    return($self);
}

sub local_firewall_rules {

    my $l = Funknet::Config::ConfigFile->local;
    my $chain = Funknet::Config::ConfigFile->whois_source || 'FUNKNET';
    debug("arrived in IPTables.pm local_firewall_rules whois_src is $chain");

    my $whole_set = `iptables -n -L $chain` ;
    my @rules = split ('\n', $whole_set);
    my @rules_out;


    foreach my $rule (@rules) {

	my ($src, $dest, $proto, $policy);
	my $type;
	chomp($rule);
	next if $rule =~ /^Chain/;
	next if $rule =~ /^target/;
	debug("$rule");
	$src = $dest = $proto = $policy = $rule;
	$policy =~ s/^(\w+).*/$1/;
	$proto =~ s/^\w+\s+(\w+).*/$1/;
	$src =~ s/^\w+\s+\w+\s+--\s+(\d+\.\d+\.\d+\.\d+).*/$1/;
	$dest =~ s/^\w+\s+\w+\s+--\s+\d+\.\d+\.\d+\.\d+\s+(\d+\.\d+\.\d+\.\d+).*/$1/;
	debug("proto is $proto");
	my $new_rule_object = Funknet::Config::FirewallRule->new(
						source => 'host',
						source_address => $src,
						destination_address => $dest,
						proto => $proto );
	debug("new_rule_object");
	push (@rules_out, $new_rule_object);
    }
    return (Funknet::Config::FirewallRuleSet::IPTables->new(
						firewall => \@rules_out,
						source => 'host'));
}

sub config {
    my ($self) = @_;

    my $l = Funknet::Config::ConfigFile->local;

    my @cmds;

    for my $fwallrule ($self->firewall) {
	if (defined $fwallrule) {
	    push @cmds, $fwallrule->create();
	}
    }
    return @cmds;
}


1;
