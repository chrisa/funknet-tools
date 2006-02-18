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


package Funknet::Config::FirewallRuleSet::PF;
use strict;
use base qw/ Funknet::Config::FirewallRuleSet /;
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallRuleSet::PF

=head1 DESCRIPTION

Provides a collection object for FirewallRule::PF objects.

=head1 METHODS

=head2 config

Returns the configuration of the FirewallRule objects as text. This
should be in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 local_firewall_rules

Returns a FirewallRuleSet::PF object representing the current
configuration of the host, or undef if the chain doesn't exist

=cut

sub new {
    my ($class, %args) = @_;
    debug("arrived in PF.pm new");
    my $self = bless {}, $class;

    $self->{_source} = $args{source};
    $self->{_firewall} = $args{firewall};

    return($self);
}

sub config {
    my ($self) = @_;

    my $l = Funknet::ConfigFile::Tools->local;

    my @cmds;
    my $whois_source = Funknet::ConfigFile::Tools->whois_source;

    my @chains = $self->chains;

    while (my $chain = pop(@chains)) {

	push @cmds, $chain->flush();

        for my $fwallrule ($chain->rules) {
	    if (defined $fwallrule) {
	        push @cmds, $fwallrule->create();
	    }
        }
    }

    my $cmdset = Funknet::Config::CommandSet->new( cmds => \@cmds,
						   target => 'host',
						 );
    
    return Funknet::Config::ConfigSet->new( cmds => [ $cmdset ] );
}

sub local_firewall_rules {
    die "PF local_firewall_rules not implemented yet";
}

1;
