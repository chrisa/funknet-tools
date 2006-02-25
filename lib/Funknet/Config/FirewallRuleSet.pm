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


package Funknet::Config::FirewallRuleSet;
use strict;
use base qw/ Funknet::Config /;
use Funknet::Config::FirewallRuleSet::IPTables;
use Funknet::Config::FirewallRuleSet::IPFW;
use Funknet::Config::FirewallRuleSet::PF;
use Funknet::Config::FirewallRuleSet::IPF;
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallRuleSet

=head1 DESCRIPTION

Provides a collection object for FirewallChains. Contains the ->diff method
for firewall. 

=head1 METHODS

# CHANGEME
=head2 new(source => 'whois', firewall => \@firewall_rules)

Takes the source and a listref of FirewallRules. 

=head2 diff($hostobj)

Called on a FirewallRuleSet object of source whois and passed a FirewallRuleSet
object of source host, returns the commands required to update the
host's firewall config to that specified in the whois.

=cut

sub new
{
    debug("arrived in FirewallRuleSet new");
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    my $l = Funknet::ConfigFile::Tools->local;

    if (defined $args{chains} && ref $args{chains} ne 'HASH') {
         debug("if defined, chains should be a hashref in FRS->new");
         return;
    }

    $self->{_chains} = $args{chains};
    $self->{_source} = $args{source};

    if (($self->{_source} eq 'whois') or ($self->{_source} eq 'host')) {
	my $subtype;
	my $firewall_type = $l->{firewall_type};
	
	if ($firewall_type eq 'iptables') {
	    $subtype = 'IPTables';
	} 
	if ($firewall_type eq 'ipfw') { 
	    $subtype = 'IPFW';
	} 
	if ($firewall_type eq 'pf') { 
	    $subtype = 'PF';
	} 
	if ($firewall_type eq 'ipf') { 
	    $subtype = 'IPF';
	} 

	my $full_object_name = "Funknet::Config::FirewallRuleSet::$subtype";
	debug("my FirewallRuleSet type is $full_object_name");
	
	bless $self, $full_object_name;
	return($self);
    }
    else
    {
    	warn("invalid source in FirewallRuleSet new");
    }
}

sub chains {
    my ($self) = @_;
    return $self->{_chains};
}

sub filter_chain {
    my ($self) = @_;
    return $self->{_chains}->{filter};
}

sub nat_chain {
    my ($self) = @_;
    return $self->{_chains}->{nat};
}

sub chain {
     my ($self, $chain) = @_;
     return $self->{_chains}->{$chain};
}

sub source {
    my ($self) = @_;
    return $self->{_source};
}

sub as_text {
    my ($self) = @_;
    if (scalar @{ $self->{_cmds} }) {
        my $text = join "\n", @{ $self->{_cmds} };
        $text .= "\n";
        return $text;
    } else {
        return '';
    }
}

sub firewall {
    my ($self) = @_;

    my @rules;

    my $filter_chain = $self->filter_chain();
    my $nat_chain = $self->nat_chain();

    push (@rules, $filter_chain->rules);
    push (@rules, $nat_chain->rules);

    return(@rules);
}

sub diff {
    my ($whois, $host) = @_;
    debug("arrived in FirewallRuleSet.pm diff");
    my @cmds;

    my $l = Funknet::ConfigFile::Tools->local;
    my $whois_source = Funknet::ConfigFile::Tools->whois_source;

    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
	$whois->warn("diff passed objects backwards");
	return undef;
    }    

    for my $chain (qw/ filter nat /) {
        push @cmds, $whois->chain($chain)->diff($host->chain($chain));
    }

    # this is right for IPTables and IPFW; when (if) we do Cisco
    # firewalling or equivalent, we'll need to move this method 
    # so we can set 'target' correctly. leave for now. 
    my $cmdset = Funknet::Config::CommandSet->new( cmds => \@cmds,
						   target => 'host',
						 );
    
    return Funknet::Config::ConfigSet->new( cmds => [ $cmdset ] );
}

sub config {
    my ($self) = @_;

    my $l = Funknet::ConfigFile::Tools->local;

    my @cmds;
    my $whois_source = Funknet::ConfigFile::Tools->whois_source;

    for my $chain_name (qw/ filter nat /) {
         my $chain = $self->chain($chain_name);
         if ($chain->needscreate eq 'yes') {
              push (@cmds, $chain->create);
         }
         
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


1;
