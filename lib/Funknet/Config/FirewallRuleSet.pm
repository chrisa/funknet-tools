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
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallRuleSet

=head1 DESCRIPTION

Provides a collection object for FirewallRules. Contains the ->diff method
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

    $self->{_firewall} = $args{firewall};
    $self->{_source}   = $args{source};
    $self->{_cmds}     = $args{cmds};

    if (($self->{_source} eq 'whois') or ($self->{_source} eq 'host')) {
	my $subtype;
	my $firewall_type = $l->{firewall_type};
	
	if ($firewall_type eq 'iptables') {
	    $subtype = 'IPTables';
	} 
	if ($firewall_type eq 'ipfw') { 
	    $subtype = 'IPFW';
	} 
	
	my $full_object_name = "Funknet::Config::FirewallRuleSet::$subtype";
	debug("my firewall type is $full_object_name");

	bless $self, $full_object_name;
	return($self);
    }
    else
    {
    	warn("invalid source in FirewallRuleSet new");
    }
}

sub firewall {
    my ($self) = @_;
    return @{$self->{_firewall}};
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

sub diff {
    my ($whois, $host) = @_;
    debug("arrived in FirewallRuleSet.pm diff");
    my (@cmds);

    my $l = Funknet::ConfigFile::Tools->local;
    my $whois_source = Funknet::ConfigFile::Tools->whois_source;

    if(! defined($host)) {
	@cmds = $whois->config();
    }
    else {

	# first check we have the objects the right way around.
	unless ($whois->source eq 'whois' && $host->source eq 'host') {
	    $whois->warn("diff passed objects backwards");
	    return undef;
	}    
    
	# create hashes
	my ($whois_fwall, $host_fwall);
	for my $fwall ($whois->firewall) {
	    $whois_fwall->{$fwall->as_hashkey} = 1;
	}
	for my $fwall ($host->firewall) {
	    $host_fwall->{$fwall->as_hashkey} = 1;
	}

	for my $h ($host->firewall) {
	    unless ($whois_fwall->{$h->as_hashkey}) {
		push @cmds, $h->delete;
	    }
	}

	for my $w ($whois->firewall) {
	    unless ($host_fwall->{$w->as_hashkey}) {
		push @cmds, $w->create;
	    }
	}
    }
    
    my $cmdset = Funknet::Config::CommandSet->new( cmds => \@cmds,
						   target => 'cli',
						 );
    
    return Funknet::Config::ConfigSet->new( cmds => [ $cmdset ] );
}

1;
