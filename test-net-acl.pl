#!/usr/bin/perl -w
use strict;
use Net::ACL;
use Net::ACL::Rule qw/ :action :rc /;
use Net::ACL::RtConfig;
use Data::Dumper;



my $list_hr = Net::ACL::RtConfig->load( dir => 'export',
					source_as => '65000',
					peer_as => '65002',
					source_addr => '10.2.0.37',
					peer_addr => '10.2.0.38',
					source => 'FUNKNET',
					host => 'whois.funknet.org',
					port => '43',
					type => 'access-list',
					protocol => 'ripe',
					name => '65002export',
				      );

my $list = Net::ACL->renew( Type => 'access-list',
			    Name => '65002export' 
			  );

my $config = $list->asconfig;

print $config;

