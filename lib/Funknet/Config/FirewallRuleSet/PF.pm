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

# XXX needs root
sub local_firewall_rules {
    my $self = shift;

    my $l = Funknet::ConfigFile::Tools->local;
    my $chain = 'FUNKNET:combo';
    debug("arrived in PF.pm local_firewall_rules whois_src is $chain");

    my @nat_rules;
    open N, "pfctl -a $chain -s nat 2>/dev/null |"
	or die "couldn't open pipe from pfctl for $chain rules";
    while (<N>) {
	chomp;
	my $line = $_;
	if ($line =~ m|^rdr inet proto (\w+) from (.*?) to (.*?) -> (.*?)$|) {
	    my ($src_a, $src_p) = _parse_addressport($2);
	    my ($dst_a, $dst_p) = _parse_addressport($3);
	    my ($nat_a, $nat_p) = _parse_addressport($4);
	    my $rule = Funknet::Config::FirewallRule->new(
		source		=> 'host',
		type		=> 'nat',
		source_address	=> $src_a,
		source_port	=> $src_p,
		destination_address	=> $dst_a,
		destination_port	=> $dst_p,
		to_addr		=> $nat_a,
		to_port		=> $nat_p,
		proto		=> $1,
	    );
	    push @nat_rules, $rule;
	}
	else {
	    $self->warn("unprocessed host fw nat rule $line");
	}	
    }
    close N;

    my @filter_rules;
    open F, "pfctl -a $chain -s rules 2>/dev/null |"
	or die "couldn't open pipe from pfctl for $chain rules";
    while (<F>) {
	chomp;
	my $line = $_;
	# since we write the rules in these chains ourselves, we don't need to
	# support the full gamut of possible rules. just as well.
	#
	if ($line =~ m|^pass| || $line =~ m|^block|) {
	    # this interface can do anything rules:
	    if ($line =~ m/^pass (in|out) on (\w+) inet all$/)  {
		my ($iif, $oif);
		if ($1 eq 'in') {
		    ($iif, $oif) = ($2, undef);
		}
		elsif ($1 eq 'out') {
		    ($iif, $oif) = (undef, $2);
		}
		else {
		    die "couldn't infer rule direction";
		}

		my $rule = Funknet::Config::FirewallRule->new(
		    source		=> 'host',
		    type		=> 'filter',
		    in_interface	=> $iif,
		    out_interface	=> $oif,
		);
		push @filter_rules, $rule;
	    } 
	    # general 
	    elsif ($line =~ m|pass inet proto (\w+) from (.*?) to (.*?)$|) {
		my ($src_a, $src_p) = _parse_addressport($2);
		my ($dst_a, $dst_p) = _parse_addressport($3);
		my $rule = Funknet::Config::FirewallRule->new(
		    source		=> 'host',
		    type		=> 'filter',
		    source_address	=> $src_a,
		    source_port		=> $src_p,
		    destination_address	=> $dst_a,
		    destination_port	=> $dst_p,
		    proto		=> $1,
		);
		push @filter_rules, $rule;
	    }
	    else {
		$self->warn("unprocessed host fw filter rule $line");
	    }	
	}
    }
    close F;

    my $filter_chain = Funknet::Config::FirewallChain->new(
	type => 'filter',
	rules => \@filter_rules,
	create => 'no',
    );
    my $nat_chain = Funknet::Config::FirewallChain->new(
	type => 'nat',
	rules => \@nat_rules,
	create => 'no',
    );
    return Funknet::Config::FirewallRuleSet->new(
	chains  => {
	    filter => $filter_chain,
	    nat    => $nat_chain,
	},
	source => 'host',
    );
}

sub _parse_addressport {
    my ($txt) = @_;
    if (!defined $txt || $txt eq '') { die "bad args to _parseaddressport"; }
    my ($a, $p);
    if ($txt =~ m|^([\d.]+)|) { $a = $1; }
    if ($txt =~ m|port = (\d+)|) {$p = $1; }
    if ($txt =~ m|port (\d+)|) {$p = $1; }
    return ($a, $p);
}

# overrides parent's diff
# it might best to call SUPER::diff and then fiddle with the ConfigSet
# that it returns, rather than maintaining this method
sub diff {
    my ($whois, $host) = @_;
    debug("arrived in FirewallRuleSet::PF.pm diff");
    my @diffs;
    my @cmds;

    my $l = Funknet::ConfigFile::Tools->local;
    my $whois_source = Funknet::ConfigFile::Tools->whois_source;

    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
	$whois->warn("diff passed objects backwards");
	return undef;
    }    

    for my $chain (qw/ filter nat /) {
        push @diffs, $whois->chain($chain)->diff($host->chain($chain));
    }
    # arrange whole anchor ruleset with NAT first
    if (scalar(@diffs)) {
	for my $chain (qw/ nat filter /) {
	    for my $rule ($whois->chain($chain)->rules()) {
		push @cmds, $rule->create();
	    }
	}
    }


    # for pfctl, we want to pipe all the commands into pfctl(8)
    my $cmdset = Funknet::Config::CommandSet->new( cmds => \@cmds,
						   diffs => \@diffs,
					   	   target => 'pfctl',
						 );
    return Funknet::Config::ConfigSet->new( cmds => [ $cmdset ] );
}

1;
