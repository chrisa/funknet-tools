package Funknet::Config::CLI::IOS;
use strict;
use Net::Telnet;

sub get_bgp {
    my ($self) = @_;

    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#]$/',
			      Port    => 23,
			    );
    
    $t->open($self->{_local_host});
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
	if ($line =~ /^\*?\>?\s+(\d+\.\d+\.\d+\.\d+)(\/\d+)?\s+0\.0\.0\.0/) {
	    push @networks, "$1$2";
	}
	if ($line =~ /^\*?\>?\s+(\d+\.\d+\.\d+\.\d+)(\/\d+)?\s+$/) {
	    $current = "$1$2";
	}
	if ($line =~ /^\s+0\.0\.0\.0/ && $current) {
	    push @networks, $current;
	}
	
    }
    
    @output = $t->cmd('show ip bgp sum');
    my $local_as;
    foreach my $line (@output) {
	if ($line =~ /local AS number (\d+)/) {
	    $local_as = "AS$1";
	}
    }

    my $bgp = Funknet::Config::BGP->new( local_as => $local_as,
					 local_router => $self->{_local_router},
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
    }
    for my $peer (keys %$neighbors) {

	my $acl_in = Funknet::Config::AccessList->new( source_as   => $bgp->{_local_as},
						       peer_as     => $neighbors->{$peer}->{remote_as},
						       source_addr => $neighbors->{$peer}->{local_addr},
						       peer_addr   => $neighbors->{$peer}->{remote_addr},
						       dir         => 'import',
						       source      => 'host',
						       local_router => 'ios',
						       local_host  => $self->{_local_host},
						     );

	my $acl_out = Funknet::Config::AccessList->new( source_as   => $bgp->{_local_as},
							peer_as     => $neighbors->{$peer}->{remote_as},
							source_addr => $neighbors->{$peer}->{local_addr},
							peer_addr   => $neighbors->{$peer}->{remote_addr},
							dir         => 'export',
							source      => 'host',
							local_router => 'ios',
							local_host  => $self->{_local_host},
						      );

	$bgp->add_session(
	    description => $neighbors->{$peer}->{description},
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

    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#]$/',
			      Port    => 23,
			    );
    
    $t->open($self->{_local_host});
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
	$acl->{_acl_text} = join "\n",@output;
    }
    if ($args{dir} eq 'export' && $acl_out) {
	@output = $t->cmd("sho ip prefix-list $acl_out");
	$acl->{_name} = $acl_out;
	$acl->{_acl_text} = join "\n",@output;
    }
    return $acl;
}


sub get_interfaces {
    my ($self) = @_;

    my @local_tun;
    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#]$/',
			      Port    => 23,
			    );
    
    $t->open($self->{_local_host});
    $t->cmd($self->{_password});
    $t->cmd('terminal length 0');

    my @output = $t->cmd('show interfaces');
    
    my $tunnels;
    my $current;
    foreach my $line (@output) {
	if ($line =~ /^(Tunnel\d+)/) {
	    $current = $1;
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
	push @local_tun,
	Funknet::Config::Tunnel->new(
	    name => $tunnels->{$tun}->{description},
	    local_address => $tunnels->{$tun}->{local_address},
	    remote_address => $tunnels->{$tun}->{remote_address},
	    local_endpoint => $tunnels->{$tun}->{local_endpoint},
	    remote_endpoint => $tunnels->{$tun}->{remote_endpoint},
	    type => $tunnels->{$tun}->{type},
	    local_os => 'ios',
	    source => 'host',
	);
    }
    return @local_tun;
}

1;