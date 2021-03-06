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

package Funknet::Config::CLI::Zebra;
use strict;
use base qw/ Funknet::Config::CLI /;
use Net::IPv4Addr qw/ ipv4_network /;
use Funknet::ConfigFile::Tools;
use Funknet::Config::CLI::Zebra::Telnet;
use Funknet::Config::CLI::Zebra::Vtysh;

=head1 NAME

Funknet::Config::CLI::Zebra;

=head1 SYNOPSIS

    my $cli = Funknet::Config::CLI->new();
    my $bgp = $cli->get_bgp;

=head1 DESCRIPTION

This module provides Zebra-specific methods for interacting with the
router's command line. Objects are instantiated through the
constructor in CLI.pm which returns an object blessed into this class
if the 'local_router' config file parameter is 'ios'.

=head1 METHODS

See the documentation in CLI.pm for methods which are available in
IOS.pm and Zebra.pm (get_bgp and get_access_list). 

=cut

sub get_bgp {
    my ($self) = @_;
    
    $self->login;
    my @output = $self->cmd('show ip bgp');

    my @networks;
    my ($current,$go,$index);
  PREFIX: foreach my $line (@output) {
	if ($line =~ /Network/) {
	    $go = 1;
	    next;
	}
	next unless $go;

	# is this a prefix line (^*)?

	my $prefix;

	if ($line =~ s/^\*//) {
	    # we have a route 
	    # grab the prefix itself

	    if ($line =~ m!>? (\d+\.\d+\.\d+\.\d+)/?(\d+)?!) {
                if (defined $2) {
		    $prefix = scalar ipv4_network("$1/$2");
                } else {
                    $prefix = scalar ipv4_network("$1");
                }
		
	    } else {
	    
		# ah. where's the prefix?
		$prefix = undef;
		next PREFIX;
	    }

	    # check if it's local

	    my @output = $self->cmd("show ip bgp $prefix");
	    
	    for my $line (@output) {
		if ($line =~ /Local/) {
		    push @networks, $prefix;
		}
	    }
	    
	} else {
	    
	    # this is a continuation

	}
    }

    @output = $self->cmd('show ip bgp sum');

    my $local_as;
    foreach my $line (@output) {
	if ($line =~ /local AS number (\d+)/) {
	    $local_as = "AS$1";
	}
	if ($line =~ /BGP not active/) {
            $local_as = 'AS00000';
        }
	if ($line =~ /No IPv4 neighbor is configured/) {
            $local_as = 'AS00000';
        }
    }
    if (!defined $local_as) {
	$local_as = 'AS00000';
    }

    my $bgp = Funknet::Config::BGP->new( local_as => $local_as,
					 routes  => \@networks,
					 source => 'host');

    @output = $self->cmd('show ip bgp neighbors');
    
    my ($neighbors, $current_neighbor);
    foreach my $line (@output) {
	if ($line =~ /^BGP neighbor is (\d+\.\d+\.\d+\.\d+), +remote AS (\d+)/) {
            next if ($2 == 0);
	    $neighbors->{$1}->{remote_as} = $2;
	    $neighbors->{$1}->{remote_addr} = $1;
	    $current_neighbor = $1;
	}
	if ($line =~ /^Local host: (\d+\.\d+\.\d+\.\d+)/ && $current_neighbor) {
	    $neighbors->{$current_neighbor}->{local_addr} = $1;
	}
	if ($line =~ /^ Description: (.+)/ && $current_neighbor) {
	    $neighbors->{$current_neighbor}->{description} = $1;
	    # Zebra gives us a rogue space here.
	    $neighbors->{$current_neighbor}->{description} =~ s/ //g;
	}
	# check this against actual zebra output
	if ($line =~ /Inbound soft reconfiguration allowed/ && $current_neighbor) {
	    $neighbors->{$current_neighbor}->{soft_reconfig} = 1;
	}
    }

  SESSION: for my $peer (keys %$neighbors) {

	# ignore_neighbor
	my @ign = Funknet::ConfigFile::Tools->ignore_neighbor();
	
	for my $ign (@ign) {
	    next SESSION if ($ign eq $neighbors->{$peer}->{remote_addr});	    
	}

	my $acl_in = Funknet::Config::AccessList->new( source_as   => $bgp->{_local_as},
						       peer_as     => $neighbors->{$peer}->{remote_as},
						       source_addr => $neighbors->{$peer}->{local_addr},
						       peer_addr   => $neighbors->{$peer}->{remote_addr},
						       dir         => 'import',
						       source      => 'host',
						     );

	my $acl_out = Funknet::Config::AccessList->new( source_as   => $bgp->{_local_as},
							peer_as     => $neighbors->{$peer}->{remote_as},
							source_addr => $neighbors->{$peer}->{local_addr},
							peer_addr   => $neighbors->{$peer}->{remote_addr},
							dir         => 'export',
							source      => 'host',
						      );
	
	$bgp->add_session(
	    description => $neighbors->{$peer}->{description},
	    soft_reconfig => $neighbors->{$peer}->{soft_reconfig},
	    remote_as => $neighbors->{$peer}->{remote_as},
	    local_addr => $neighbors->{$peer}->{local_addr},
	    remote_addr => $neighbors->{$peer}->{remote_addr},
	    acl_in => $acl_in, 
	    acl_out => $acl_out,
	);
    }
    $self->logout;
    return $bgp;
}

sub get_access_list {
    my ($self, %args) = @_;
    
    $self->login;
    my @output = $self->cmd("show ip bgp neighbor $args{remote_addr}");
    
    my ($acl_in, $acl_out);
    foreach my $line (@output) {
	if ($line =~ /Route map for incoming advertisements is \*(.+)/) {
	    $acl_in = $1;
	}
	if ($line =~ /Route map for outgoing advertisements is \*(.+)/) {
	    $acl_out = $1;
	}
    }

    my $acl;
    if ($args{dir} eq 'import' && defined $acl_in) {
	@output = $self->cmd("sho ip prefix-list $acl_in");
	$acl->{_name} = $acl_in;
	$acl->{_acl_text} = _to_text(@output);
    }
    if ($args{dir} eq 'export' && defined $acl_out) {
	@output = $self->cmd("sho ip prefix-list $acl_out");
	$acl->{_name} = $acl_out;
	$acl->{_acl_text} = _to_text(@output);
    }
    $self->logout;

    if (defined $acl->{_name} && defined $acl->{_acl_text}) {
	return $acl;
    } else {
	return undef;
    }
}

sub _to_text {
    my @lines = @_;
    my ($text,$name);

    for my $line (@lines) {
	if ($line =~ /ip\s+prefix-list\s+([A-Za-z0-9-]+):\s+(\d+)\s+entr/) {
	    $name = $1;
	} 
	if ($name && $line =~ /\s+seq\s\d+\s(.*)$/) {
	    my $rule = $1;
	    $text .= "ip prefix-list $name $rule\n";
	}
    }
    return $text;
}

=head2 get_as

Get the asn for an ip address from our local funknet router. Inspired
by ztraceroute.

=cut

sub get_as {
    my ($self, $address) = @_;
    defined ($self->{t}) or return undef;

    my @output = $self->cmd("sho ip bgp $address");

    for my $line (@output) {
	chomp $line;
	my ($asnum) = $line =~ /^[\d\s]*\s(\d+)$/;
	return $asnum if $asnum;
	
	($asnum) = $line =~ /aggregated by (\d+) /;
	return $asnum if $asnum;
    }
    return undef;
}

1;
