package Funknet::Config::CLI::Zebra;
use strict;
use Net::Telnet;

=head1 NAME

Funknet::Config::CLI::Zebra;

=head1 SYNOPSIS

    my $cli = Funknet::Config::CLI->new( local_as => 'AS65000',
					 local_host => '127.0.0.1',
					 local_router => 'zebra',
				       );
    my $bgp = $cli->get_bgp;

=head1 DESCRIPTION

This module provides Zebra-specific methods for interacting with the
router's command line. Objects are instantiated through the
constructor in CLI.pm which returns an object blessed into this class
if the 'local_router' argument is 'ios'.

=head1 METHODS

See the documentation in CLI.pm for methods which are available in
IOS.pm and Zebra.pm (get_bgp and get_access_list). 

=cut

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

	my $acl_in = Funknet::Config::AccessList->new( source_as   => $bgp->{_local_as},
						       peer_as     => $neighbors->{$peer}->{remote_as},
						       source_addr => $neighbors->{$peer}->{local_addr},
						       peer_addr   => $neighbors->{$peer}->{remote_addr},
						       dir         => 'import',
						       source      => 'host',
						       local_router => 'zebra',
						       local_host  => $self->{_local_host},
						     );

	my $acl_out = Funknet::Config::AccessList->new( source_as   => $bgp->{_local_as},
							peer_as     => $neighbors->{$peer}->{remote_as},
							source_addr => $neighbors->{$peer}->{local_addr},
							peer_addr   => $neighbors->{$peer}->{remote_addr},
							dir         => 'export',
							source      => 'host',
							local_router => 'zebra',
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
			      Prompt  => '/[\>\#] $/',
			      Port    => 2605,
			    );
    
    $t->open($self->{_local_host});
    $t->cmd($self->{_password});
    $t->cmd('terminal length 0');

    my @output = $t->cmd("show ip bgp neighbor $args{remote_addr}");
    
    my ($acl_in, $acl_out);
    foreach my $line (@output) {
	if ($line =~ /Route map for incoming advertisements is (.+)/) {
	    $acl_in = $1;
	}
	if ($line =~ /Route map for outgoing advertisements is (.+)/) {
	    $acl_out = $1;
	}
    }

    my $acl;
    if ($args{dir} eq 'import') {
	@output = $t->cmd("sho ip prefix-list $acl_in");
	$acl->{_name} = $acl_in;
	$acl->{_acl_text} = join "\n",@output;
    }
    if ($args{dir} eq 'export') {
	@output = $t->cmd("sho ip prefix-list $acl_out");
	$acl->{_name} = $acl_out;
	$acl->{_acl_text} = join "\n",@output;
    }
    return $acl;

}

sub check_login {
    my ($self) = @_;

    return 1;
    
    my $t = new Net::Telnet ( Timeout => 10,
			      Prompt  => '/[\>\#]$/',
			      Port    => 2605,
			    );
    $t->open($self->{_local_host});
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


1;
