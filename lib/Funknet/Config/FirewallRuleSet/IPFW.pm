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


package Funknet::Config::FirewallRuleSet::IPFW;
use strict;
use base qw/ Funknet::Config::FirewallRuleSet /;
use Funknet::Debug;

use Data::Dumper;

=head1 NAME

Funknet::Config::FirewallRuleSet::IPFW

=head1 DESCRIPTION

Provides a collection object for FirewallRule::IPFW objects.

In order to acheive poking holes into the ruleset without re-running
the firewall script, these tools only pay attention to rules within
the range min_ipfw_rule and max_ipfw_rule as specified in the config
file. Arrange for the rest of your ruleset to be placed around these
accordingly.

=head1 METHODS

=head2 config

Returns the configuration of the FirewallRule objects as text. This
should be in roughly the format used by the host. TODO: make this be
so. Currently we just dump the information in an arbitrary format.

=head2 local_firewall_rules

Returns a FirewallRuleSet::IPFW object representing the current 
configuration of the host

=head2 diff($hostobj)

IPFW specific diff, overrides the generic one in FirewallRuleSet.pm
Called on a FirewallRuleSet object of source whois and passed one of
source host, returns the commands required to update the host's
firewall config to that in the whois

=cut

sub local_firewall_rules {

    my $l = Funknet::ConfigFile::Tools->local;
    debug("arrived in IPFW.pm local_firewall_rules");

    my $whole_set = `ipfw list` ;
    my @rules = split ('\n', $whole_set);
    my @filter_rules_out;

    foreach my $rule (@rules) {

	my ($src, $dest, $proto, $policy, $src_port, $dst_port, $in_if, $out_if);
	my ($first_half, $second_half);
	my $rule_num;
	chomp($rule);

	$rule_num = $rule;
	$rule_num =~ s/^(\d+).*/$1/;

	next unless(($rule_num <= $l->{max_ipfw_rule}) && ($rule_num >= $l->{min_ipfw_rule}));	
	debug("rule number $rule_num in range");
	debug("rule is $rule");

	($first_half, $second_half) = split ('to', $rule);

	if ($first_half =~ s/^\d+\s(\S+)\s(\S+)\sfrom\s(\d+\.\d+\.\d+\.\d+)(?:\/\d+)?\ (\d+).*/$1,$2,$3,$4/) {  
	    ($policy, $proto, $src, $src_port) = split(',',$first_half);
	} elsif ($first_half =~ s/^\d+\s(\S+)\s(\S+)\sfrom\s(any).*/$1,$2,$3/) {
	    ($policy, $proto, $src) = split(',',$first_half);
	} else {
	    $first_half =~ s/^\d+\s(\S+)\s(\S+)\sfrom\s(\d+\.\d+\.\d+\.\d+)(?:\/\d+)?.*/$1,$2,$3/;
	    ($policy, $proto, $src) = split(',',$first_half);
	    $src_port = undef;
	}

	if ($second_half =~ /any/) {
	    if ($second_half =~ /in/) {
                if ($second_half =~ s/^\ (any)\ (\d+) in\ recv\ ([a-z]+[0-9]+)/$1,$2,$3/) {
	            ($dest, $dst_port, $in_if) = split(',', $second_half);
		} else {
		    $second_half =~ s/^\ (any)\ in\ recv\ ([a-z]+[0-9]+)/$1,$2/;
		    $dst_port = '';
		    ($dest, $in_if) = split(',', $second_half);
		    debug("dest: $dest, in_if: $in_if");
		}

	    } elsif ($second_half =~ /out/) {
                if ($second_half =~ s/^\ (any)\ (\d+) out\ xmit\ ([a-z]+[0-9]+)/$1,$2,$3/) {
	            ($dest, $dst_port, $out_if) = split(',', $second_half);
		} else {
		    $second_half =~ s/^\ (any)\ out\ xmit\ ([a-z]+[0-9]+)/$1,$2/;
		    $dst_port = '';
		    ($dest, $out_if) = split(',', $second_half);
		    debug("dest: $dest, out_if: $out_if");
		}

	    } else {

	        if ($second_half =~ s/^\ (any)\ (?:\d+\ )?.*/$1,$2/) {
	            ($dest, $dst_port) = split(',', $second_half);
	        } else {
		    $dest = 'any';
		}
	    }
	} else {

            if ($second_half =~ /in/) {
                if ($second_half =~ s/^\ (\d+\.\d+\.\d+\.\d+)\ dst-port\ (\d+)\ in\ recv\ ([a-z]+[0-9]+)/$1,$2,$3/) {
		    debug("port");
                    ($dest, $dst_port, $in_if) = split(',', $second_half);
		} else {
                    $second_half =~ s/^\ (\d+\.\d+\.\d+\.\d+)\ in\ recv\ ([a-z]+[0-9]+)/$1,$2/;
		    debug("no port");
                    ($dest, $in_if) = split(',', $second_half);
		}

            } elsif ($second_half =~ /out/) {

                $second_half =~ s/^\ (\d+\.\d+\.\d+\.\d+)(?:\/\d+)?\ (?:\d+\ )?out\ xmit\ ([a-z]+[0-9]+)/$1,$2,$3/;
                ($dest, $out_if) = split(',', $second_half);

            } else {

                if ($second_half =~ s/^\ (\d+\.\d+\.\d+\.\d+)(?:\/\d+)?\ dst-port\ (\d+).*/$1,$2/) {
		    ($dest, $dst_port) = split(',', $second_half);
		} else {
		    $second_half =~ s/^\ (\d+\.\d+\.\d+\.\d+)(?:\/\d+)?.*/$1/;
                    $dest = $second_half;
		}
	    }
	}

	debug("src: $src, dest: $dest, proto: $proto, policy: $policy");
	debug("src_port: $src_port, dst_port: $dst_port, in_if: $in_if, out_if: $out_if");

	unless ($src_port =~ /\d+/) {
	    $src_port = undef;
	}
	unless ($dst_port =~ /\d+/) {
	    $dst_port = undef;
	}

	if ($proto eq 'ip') { $proto = 'all';}
	debug("proto is $proto");

	if ($src eq 'any') { $src = '0.0.0.0/0';}
	if ($dest eq 'any') { $dest = '0.0.0.0/0';}

	my $new_rule_object =
	  Funknet::Config::FirewallRule->new(
					source               => 'host',
					source_address       => $src,
					source_port          => $src_port,

					destination_address  => $dest,
					destination_port     => $dst_port,

					proto                => $proto,
					in_interface         => $in_if,
					out_interface        => $out_if,
					rule_num             => $rule_num );
	push (@filter_rules_out, $new_rule_object);
    }

    my $filter_chain =  Funknet::Config::FirewallChain->new(
							type	=> 'filter',
							rules	=> \@filter_rules_out,
							create	=> 'no',
							);

    warn("creating empty nat chain as we are IPFW");

    my $empty_nat_chain =  Funknet::Config::FirewallChain->new(
							type	=> 'nat',
							rules	=> [],
							create	=> 'no',
							);

    return Funknet::Config::FirewallRuleSet->new( chains  => {
								filter => $filter_chain,
								nat    => $empty_nat_chain,
							     },
						  source  => 'host' );

}

sub add {
    my ($self, $rule) = @_;
    debug("arrived in FirewallRuleSet::IPFW add");

    my $l = Funknet::ConfigFile::Tools->new;
    my @rules = $self->firewall;
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
	$rule->rule_num($next_rule_num);
	push (@rules, $rule);
    }

    return(Funknet::Config::FirewallRuleSet->new(firewall => \@rules,
					source => 'host'), $next_rule_num);
}

sub config {
    my ($self) = @_;

    my $l = Funknet::ConfigFile::Tools->local;
    my $rule_num = $l->{min_ipfw_rule};

    my @cmds;

    for my $fwallrule ($self->firewall) {
	if($rule_num <= $l->{max_ipfw_rule}) {
	    push @cmds, $fwallrule->create($rule_num);
	    $rule_num++;
	} else
	{
	    die("ran out of available firewall entries");
	}
    }

    my $cmdset = Funknet::Config::CommandSet->new( cmds => \@cmds,
						   target => 'host',
						 );
    
    return Funknet::Config::ConfigSet->new( cmds => [ $cmdset ] );
}

1;
