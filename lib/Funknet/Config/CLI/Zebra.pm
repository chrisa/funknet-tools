package Funknet::Config::CLI::Zebra;
use strict;
use Net::Telnet;

sub get_bgp {
    my ($self) = @_;

    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#] $/',
			      Port    => 2605,
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

    @output = $t->cmd('show ip bgp neighbors');
    
    my ($neighbors, $current_neighbor, $local_as);
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
	if ($line =~ /local AS (\d+)/) {
	    $local_as = "AS$1";
	}
    }

    my $bgp = Funknet::Config::BGP->new( local_as => $local_as,
					 local_router => $self->{_local_router},
					 routes  => \@networks,
					 source => 'host');

    for my $peer (keys %$neighbors) {
	$bgp->add_session(
	    description => $neighbors->{$peer}->{description},
	    remote_as => $neighbors->{$peer}->{remote_as},
	    local_addr => $neighbors->{$peer}->{local_addr},
	    remote_addr => $neighbors->{$peer}->{remote_addr},
	);
    }
    return $bgp;
}

1;
