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

Funknet::Config::FirewallRuleSet::IPTables

=head1 DESCRIPTION

Provides a collection object for FirewallRule::IPTables objects.

=head1 METHODS

=head2 config

Returns the configuration of the FirewallRule objects as text. This
should be in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 local_firewall_rules

Returns a FirewallRuleSet::IPTables object representing the current
configuration of the host, or undef if the chain doesn't exist

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

    my $l = Funknet::ConfigFile::Tools->local;
    my $chain = Funknet::ConfigFile::Tools->whois_source || 'FUNKNET';
    debug("arrived in IPTables.pm local_firewall_rules whois_src is $chain");

    if(my $whole_set = `iptables -v -n -L $chain`) {

	my @rules = split ('\n', $whole_set);
	my @rules_out;

	foreach my $rule (@rules) {
	    my ($src, $dest, $proto, $policy, $src_port, $dst_port);
	    chomp($rule);
	    next if $rule =~ /^Chain/;
	    next if $rule =~ /target/;
	    debug("$rule");
	    $src_port = $dst_port = $src = $dest = $proto = $policy = $rule;

	    $policy =~ s/^\s+\d+\s+\d+\s+(\w+).*/$1/;
	    $proto =~ s/^\s+\d+\s+\d+\s+\w+\s+(\w+).*/$1/;
	    if($proto == 4) { $proto = 'ipencap' };

	    $src =~ s/^\s+\d+\s+\d+\s+\w+\s+\w+\s+--\s+\S+\s+\S+\s+(\d+\.\d+\.\d+\.\d+).*/$1/;
	    $dest =~ s/^\s+\d+\s+\d+\s+\w+\s+\w+\s+--\s+\S+\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+(\d+\.\d+\.\d+\.\d+).*/$1/;

	    if($src_port =~ /spt:/) {
	        $src_port =~ s/^\s+\d+\s+\d+\s+\w+\s+\w+\s+--\s+\S+\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\w+\s+spt:(\d+).*/$1/;
	    } else {
	        $src_port = undef;
	    }

	    if($dst_port =~ /dpt:/) {
	        $dst_port =~ s/.*dpt:(\d+).*/$1/;
	    } else {
	        $dst_port = undef;
	    }


	    debug("proto is $proto");
	    my $new_rule_object = Funknet::Config::FirewallRule->new(
						  source => 'host',
						  source_address => $src,
						  source_port => $src_port,
						  destination_address => $dest,
						  destination_port => $dst_port,
						  proto => $proto );
	    debug("new_rule_object");
	    push (@rules_out, $new_rule_object);
	}
	return Funknet::Config::FirewallRuleSet::IPTables->new(
							       firewall => \@rules_out,
							       source => 'host'
							      );
    } else {
	# explicitly empty RuleSet
	return Funknet::Config::FirewallRuleSet::IPTables->new(
							       firewall => [],
							       source => 'host'
							      );
    }
}

sub config {
    my ($self) = @_;

    my $l = Funknet::ConfigFile::Tools->local;

    my @cmds;
    my $whois_source = Funknet::ConfigFile::Tools->whois_source;
    my $first_rule = Funknet::Config::FirewallRule::IPTables->create_chain($whois_source);

    push (@cmds, $first_rule);

    for my $fwallrule ($self->firewall) {
	if (defined $fwallrule) {
	    push @cmds, $fwallrule->create();
	}
    }

    my $cmdset = Funknet::Config::CommandSet->new( cmds => \@cmds,
						   target => 'cli',
						 );
    
    return Funknet::Config::ConfigSet->new( cmds => [ $cmdset ] );
}

1;
