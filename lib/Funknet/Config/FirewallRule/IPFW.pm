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


package Funknet::Config::FirewallRule::IPFW;
use strict;
use base qw/ Funknet::Config::FirewallRule /;
use Funknet::ConfigFile::Tools;
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallRule::IPFW

=head1 DESCRIPTION

This class contains methods for creating and deleting rules from an IPFW
ruleset.

=head1 METHODS

=head2 create

Returns a list of strings containing commands to create an IPFW rule
of specified number. The rule details are passed in as part of $self,
and the rule number to use is passed in as a seperate arguement.

=head2 delete

Returns a list of strings containing commands to delete an IPFW rule
from the ruleset.

=cut

sub delete {
    my ($self) = @_;

    my $whois_source = Funknet::ConfigFile::Tools->whois_source || 'FUNKNET';

    return ("ipfw del $self->{_rule_num}");
}

sub create {

    my ($self, $rule_num) = @_;

    my $whois_source = Funknet::ConfigFile::Tools->whois_source || 'FUNKNET';
    
    if (defined $self->{_source_port} && defined $self->{_destination_port}) {
	return ("ipfw add $rule_num allow $self->{_proto} from $self->{_source_address} $self->{_source_port} " .
		"to $self->{_destination_address} $self->{_destination_port}");
    } else {
	return ("ipfw add $rule_num allow $self->{_proto} from $self->{_source_address} to $self->{_destination_address}");
    }
}
1;
