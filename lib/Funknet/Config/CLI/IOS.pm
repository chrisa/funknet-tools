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


package Funknet::Config::CLI::IOS;
use strict;
use Net::Telnet;
use Network::IPv4Addr qw/ ipv4_network /;

=head1 NAME

Funknet::Config::CLI::IOS;

=head1 SYNOPSIS

    my $cli = Funknet::Config::CLI->new();
    my $bgp = $cli->get_bgp;

=head1 DESCRIPTION

This module provides IOS-specific methods for interacting with the
router's command line. Objects are instantiated through the
constructor in CLI.pm which returns an object blessed into this class
if the config file specifies a local_router of 'ios'

=head1 METHODS

See the documentation in CLI.pm for methods which are available in
IOS.pm and Zebra.pm (get_bgp and get_access_list). 

=head2 get_interfaces

This method retrieves the tunnel configuration from the running IOS
router. It is assumed that tunnel interfaces are all named 'Tunnel$n'
on IOS. Information is taken from 'sho inter' so that enable mode is
not needed.

=cut

sub get_bgp { 
    my ($self) = @_;
    my $l = Funknet::Config::ConfigFile->local;
    
    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#]$/',
			      Port    => 23,
			    );
    
    $t->open($l->{host});
    $t->cmd($self->{_password});
    $t->cmd('terminal length 0');
    
    my @output = $t->cmd('show ip bgp');

    my @networks;
    my ($current,$go);
    foreach my $line (@output) {
	if ($line =~ /Network/) {
	    $go = 1;
	    next;
	}
	next unless $go;
#       if ($line =~ /^\*?\>?\s+(\d+\.\d+\.\d+\.\d+)(\/\d+)?\s+0\.0\.0\.0/) {
# 	    push @networks, "$1$2";
# 	}
# 	if ($line =~ /^\*?\>?\s+(\d+\.\d+\.\d+\.\d+)(\/\d+)?\s+$/) {
# 	    $current = "$1$2";
# 	}
# 	if ($line =~ /^\s+0\.0\.0\.0/ && $current) {
# 	    push @networks, $current;
# 	}

	if ($line =~ /^\*?\>?\s+(\d+\.\d+\.\d+\.\d+)(\/\d+)?\s+\d.{40}i/ && !defined $current) {
	    if(!defined($2))
	    {
		push @networks, scalar ipv4_network("$1");
	    }
	    else
	    {
		push @networks, scalar ipv4_network("$1$2");
	    }
 	}
	if ($line =~ /^\*?\>?\s+(\d+\.\d+\.\d+\.\d+)(\/\d+)?\s+$/) {
 	    $current = "$1$2";
 	}
 	if ($line =~ /^.{61}i/ && $current) {
 	    push @networks, scalar ipv4_network($current);
	    undef $current;
 	}
	
    }
    
    @output = $t->cmd('show ip bgp sum');
    my $local_as;
    foreach my $line (@output) {
	if ($line =~ /local AS number (\d+)/) {
	    $local_as = "AS$1";
	}
	if ($line =~ /BGP not active/) {
            $local_as = 'AS00000';
        }
    }
    if (!defined $local_as) {
	$local_as = 'AS00000';
    }
    
    my $bgp = Funknet::Config::BGP->new( local_as => $local_as,
					 routes  => \@networks,
					 source => 'host');

    @output = $t->cmd('show ip bgp neighbors');
    
    my ($neighbors, $current_neighbor);
    foreach my $line (@output) {
	if ($line =~ /^BGP neighbor is (\d+\.\d+\.\d+\.\d+), +remote AS (\d+)/) {
	    $neighbors->{$1}->{remote_as} = $2;
	    $neighbors->{$1}->{remote_addr} = $1;
	    $current_neighbor = $1;
	}
	if ($line =~ /^Local host: (\d+\.\d+\.\d+\.\d+)/ && $current_neighbor) {
	    $neighbors->{$current_neighbor}->{local_addr} = $1;
	}
	if ($line =~ /^ Description: (.+)/ && $current_neighbor) {
	    $neighbors->{$current_neighbor}->{description} = $1;
	}
	if ($line =~ /Inbound soft reconfiguration allowed/ && $current_neighbor) {
	    $neighbors->{$current_neighbor}->{soft_reconfig} = 1;
	}
    }
    for my $peer (keys %$neighbors) {

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
    return $bgp;
}

sub get_access_list {
    my ($self, %args) = @_;
    my $l = Funknet::Config::ConfigFile->local;

    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#]$/',
			      Port    => 23,
			    );
    
    $t->open($l->{host});
    $t->cmd($self->{_password});
    $t->cmd('terminal length 0');

    my @output = $t->cmd("show ip bgp neighbor $args{remote_addr}");
    
    my ($acl_in, $acl_out);
    foreach my $line (@output) {
	if ($line =~ /Route map for incoming advertisements is ([a-zA-Z0-9-]+)/) {
	    $acl_in = $1;
	}
	if ($line =~ /Route map for outgoing advertisements is ([a-zA-Z0-9-]+)/) {
	    $acl_out = $1;
	}
    }

    my $acl;
    if ($args{dir} eq 'import' && $acl_in) {
	@output = $t->cmd("sho ip prefix-list $acl_in");
	$acl->{_name} = $acl_in;
	$acl->{_acl_text} = _to_text(@output);
    }
    if ($args{dir} eq 'export' && $acl_out) {
	@output = $t->cmd("sho ip prefix-list $acl_out");
	$acl->{_name} = $acl_out;
	$acl->{_acl_text} = _to_text(@output);
    }

    return $acl;
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
	
	
sub get_interfaces {
    my ($self) = @_;
    my $l = Funknet::Config::ConfigFile->local;

    my @local_tun;
    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#]$/',
			      Port    => 23,
			    );
    
    $t->open($l->{host});
    $t->cmd($self->{_password});
    $t->cmd('terminal length 0');

    my @output = $t->cmd('show interfaces');
    
    my $tunnels;
    my $current;
    foreach my $line (@output) {
	if ($line =~ /^(Tunnel)(\d+)/) {
	    $current = "$1$2";
	    $tunnels->{$current}->{interface} = $2;
	}
	if ($line =~ /^\s+Internet address is (\d+\.\d+\.\d+)\.(\d+)/ && $current) {
	    my $addr = $1;
	    my $local_last = $2;
	    my $remote_last;
	    if ($local_last % 2) {
		$remote_last = $local_last + 1;
	    } else {
		$remote_last = $local_last - 1;
	    }
	    $tunnels->{$current}->{local_address} = $addr.'.'.$local_last;
	    $tunnels->{$current}->{remote_address} = $addr.'.'.$remote_last;
	}
	if ($line =~ /\s+Tunnel source (\d+\.\d+\.\d+\.\d+) \(.+\), destination (\d+\.\d+\.\d+\.\d+)/ && $current) {
	    $tunnels->{$current}->{local_endpoint} = $1;
	    $tunnels->{$current}->{remote_endpoint} = $2;
	}
	if ($line =~ /\s+Description: (.+)/ && $current) {
	    $tunnels->{$current}->{description} = $1;
	}
	if ($line =~ /Tunnel protocol\/transport (.+?),/ && $current) {
	    ($1 eq 'IP/IP') and $tunnels->{$current}->{type} = 'ipip';
	    ($1 eq 'GRE') and $tunnels->{$current}->{type} = 'gre';
	}
    }

    for my $tun (keys %$tunnels) {
	my $new_tun = 
	    Funknet::Config::Tunnel->new(
		name => $tunnels->{$tun}->{description},
		local_address => $tunnels->{$tun}->{local_address},
		remote_address => $tunnels->{$tun}->{remote_address},
		local_endpoint => $tunnels->{$tun}->{local_endpoint},
		remote_endpoint => $tunnels->{$tun}->{remote_endpoint},
		type => $tunnels->{$tun}->{type},
		ifname => $tun,
		interface => $tunnels->{$tun}->{interface},
		source => 'host',
		proto => '4',
	    );
	if (defined $new_tun) {
	    push @local_tun, $new_tun;
	}
    }
    return @local_tun;
}

sub check_login {
    my ($self) = @_;
    my $l = Funknet::Config::ConfigFile->local;

    return 1;
    
    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#] $/',
			      Port    => 23,
			    );
    $t->open($l->{host});
    $t->cmd($self->{_password});
    $t->getline;
    $t->cmd('enable');
    $t->cmd($self->{_enable});
    my $p = $t->getline;
    if ($p =~ /#/) {
	return 1;
    } else {
	return undef;
    }
}

sub exec_enable {
    my ($self, $cmdset) = @_;
    my $l = Funknet::Config::ConfigFile->local;

    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[ \>\#]$/',
			      Port    => 23,
			    );
    $t->input_log(\*STDOUT);
    $t->open($l->{host});
    $t->cmd($self->{_password});
    $t->cmd('terminal length 0');
    $t->cmd('enable');
    $t->cmd($self->{_enable});
    for my $cmd ($cmdset->cmds) {
	for my $cmd_line (split /\n/, $cmd) {
	    $t->cmd($cmd_line);
	    sleep 2;
	}
    }
    $t->cmd('disable');
    $t->close;
}

1;
