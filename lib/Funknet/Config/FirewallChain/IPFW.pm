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


package Funknet::Config::FirewallChain::IPFW;
use strict;
use base qw/ Funknet::Config::FirewallChain /;
use Funknet::Config;
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallChain::IPFW

=head1 DESCRIPTION

Provides a collection object for FirewallChain::IPFW objects.

=head1 METHODS

=head2 initialise

Make sure to return an empty set of rules if type is nat

=cut

sub initialise
{
    my ($self) = @_;

    if ($self->{_type} eq 'nat' ) {
	warn("NAT is not supported with IPFW");
	$self->{_rules} = [];
    }
}

sub diff {
    my ($whois, $host) = @_;
    debug("arrived in FirewallChain::IPFW.pm diff");
    my (@cmds);
 
    debug("whois is");
    print Dumper $whois;
    debug("host is");
    print Dumper $host;

    my $whois_source = Funknet::ConfigFile::Tools->whois_source;

    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
        $whois->warn("diff passed objects backwards");
        return undef;
    }
 
    # create hashes
 
    my ($whois_fwall, $host_fwall, $tmp_fwall, $new_fwall);
    my @rules;
 
    for my $fwall ($whois->firewall) {
        $whois_fwall->{$fwall->as_hashkey} = 1;
    }
    for my $fwall ($host->firewall) {
        $host_fwall->{$fwall->as_hashkey} = 1;
    }
 
    $tmp_fwall = $host->copy;
 
    debug("tmp_fwall is");
    print Dumper $tmp_fwall;
 
    for my $h ($host->firewall) {
        unless ($whois_fwall->{$h->as_hashkey}) {
            push @cmds, $h->delete;
            $new_fwall = $tmp_fwall->remove($h);
            $tmp_fwall = $new_fwall;
        }
    }
 
    for my $w ($whois->firewall) {
        unless ($host_fwall->{$w->as_hashkey}) {
            my $new_rule_num;
            ($new_fwall, $new_rule_num) = $tmp_fwall->add($w);
            $tmp_fwall = $new_fwall;
            push @cmds, $w->create($new_rule_num);
        }
    }
 
    my $cmdset = Funknet::Config::CommandSet->new( cmds => \@cmds,
                                                   target => 'host',
                                                 );
 
    return Funknet::Config::ConfigSet->new( cmds => [ $cmdset ] );
}

1;
