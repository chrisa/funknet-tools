#!/usr/bin/perl -w
use strict;

use GraphViz;
use IO::Socket::INET;
use Data::Dumper;

my $g = GraphViz->new(layout => 'neato',
		      no_overlap => 1,
		      directed => 0 );

my $central = $ARGV[0];

my $sock = IO::Socket::INET->new( PeerAddr => '62.169.139.122',
				  PeerPort => 43,
				  Proto    => 'tcp',
				);
print $sock $central;
print $sock "\n";

while (my $line = <$sock>) {
    next unless ($line =~ /^members: +(AS\d+)/);
    my $as = $1;
    
#    print STDERR "adding $as\n";
#    $g->add_node($as);
    
    my $as_sock = IO::Socket::INET->new( PeerAddr => '62.169.139.122',
					 PeerPort => 43,
					 Proto    => 'tcp',
				       );
    print $as_sock $as;
    print $as_sock "\n";
    
    my $name;
    while (my $as_line = <$as_sock>) {
	if ($as_line =~ /^tun: +(.*)/) {
	    print STDERR "got tun: $1\n";
	    my $tun = $1;
	    
	    my $tun_sock = IO::Socket::INET->new( PeerAddr => '62.169.139.122',
						  PeerPort => 43,
						  Proto    => 'tcp',
						);
	    print $tun_sock $tun;
	    print $tun_sock "\n";
	    
	    my @tun_as;
	    while (my $tun_line = <$tun_sock>) {
		next unless ($tun_line =~ /^as: +(AS\d+)/);
		print STDERR "got as: $1\n";
		my $tun_as = $1;
		push @tun_as, $tun_as;
	    }
	    
	    if (scalar @tun_as == 2) {
		print STDERR "adding tunnel from $tun_as[0] to $tun_as[1]\n";
		$g->add_edge(@tun_as);
	    }
	    
	} elsif ($as_line =~ /^as-name: +(.*)/) {
	    
	    $name = $1;
	    
	}
    }
    $g->add_node($as, label => $name);
    
}

print $g->as_jpeg;

