package Funknet::WebServices::IRR;
use strict;
use Data::Dumper;
# This module contains the code to drive RtConfig etc. 

use subs qw/ RtConfig /;
use Digest::MD5 'md5_hex';

1;

sub new {
    my ($class) = @_;

    print STDERR "in IRR::new\n";

    my $self = bless {}, $class;
    return $self;
}

sub RtConfig {
    my ($self, $dir, $source_as, $peer_as, $source_addr, $peer_addr) = @_;
    
    print Dumper \@_;

    my $rtconfig = 
	'/usr/local/bin/RtConfig -h whois.funknet.org -p 43 -s FUNKNET -protocol ripe ' . 
	'-config cisco -cisco_use_prefix_lists';

    my $command = 
	'@RtConfig '.$dir.' AS'.$source_as.' '.$source_addr.' AS'.
	$peer_as.' '.$peer_addr."\n";

    my @output = `echo '$command' | $rtconfig`;
    
    my $acl_text = '';
    my $acl_name;
    for my $line (@output) {
	next unless ($line =~ /^ip prefix-list/);
	$acl_name = $peer_as.$dir;
	$line =~ s/pl100/$acl_name/;
	$acl_text .= $line;
    }

    return "access-list failed" unless $acl_text;
    return $acl_text;
}

