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
	$self->warn("NAT is not supported with IPFW");
	$self->{_rules} = [];
    }
}

sub diff {
    my ($whois, $host) = @_;
    debug("arrived in FirewallChain::IPFW.pm diff");
    my (@cmds);
 
    # create hashes
 
    my ($whois_fwall, $host_fwall, $tmp_fwall, $new_fwall);
    my @rules;
 
    for my $fwall ($whois->rules) {

        $whois_fwall->{$fwall->as_hashkey} = 1;
    }
    for my $fwall ($host->rules) {
        $host_fwall->{$fwall->as_hashkey} = 1;
    }
 
    $tmp_fwall = $host->copy;
 
    for my $h ($host->rules) {
        unless ($whois_fwall->{$h->as_hashkey}) {
            push @cmds, $h->delete;
            $new_fwall = $tmp_fwall->remove($h);
            $tmp_fwall = $new_fwall;
        }
    }
 
    for my $w ($whois->rules) {
        unless ($host_fwall->{$w->as_hashkey}) {
            my $new_rule_num;
            ($new_fwall, $new_rule_num) = $tmp_fwall->add($w);
            $tmp_fwall = $new_fwall;
            push @cmds, $w->create($new_rule_num);
        }
    }
 
    return @cmds;
}

sub copy {
    my ($self) = @_;
    debug("arrived in FirewallChain::IPFW.pm copy");
    my $class = ref $self;
    my $copy = bless {}, $class;
    %$copy = %$self;

    return($copy);
}

sub remove {
    my ($self, $rule) = @_;

    my @rules;

    foreach my $local_rule ($self->rules) {
        unless($rule->as_hashkey eq $local_rule->as_hashkey) {
            push (@rules, $local_rule);
        }
    }

    my $new_fwall = Funknet::Config::FirewallChain->new(rules	=> \@rules,
                                                        source	=> 'host');
    return($new_fwall);
}

sub add {
    my ($self, $rule) = @_;

    my $l = Funknet::ConfigFile::Tools->new;
    my @rules = $self->rules;
    my $free;
    my $next_rule_num;

    for(my $c=$l->min_ipfw_rule ; $c<=$l->max_ipfw_rule ; $c++) {
        $free = 'yes';

        foreach my $local_rule (@rules) {
            my $lerc = $local_rule->rule_num;
            if($local_rule->rule_num == $c) { $free = 'no' ; last };
        }
        if($free eq 'yes') {$next_rule_num = $c ; last}
    }
    if($free eq 'no') {
        die("ran out of free firewall rules");
    } else {
	debug("adding rule as number $next_rule_num");
        $rule->rule_num($next_rule_num);
        push (@rules, $rule);
    }
        
    my $new_chain = Funknet::Config::FirewallChain->new(rules => \@rules,
						source => 'host');
    return($new_chain, $next_rule_num);
}

1;
