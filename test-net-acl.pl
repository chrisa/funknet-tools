#!/usr/bin/perl -w
use strict;
use Net::ACL;
use Net::ACL::Rule qw/ :action :rc /;
use Net::ACL::RtConfig;

my $list_hr = load Net::ACL::RtConfig( dir => 'import',
				       source_as => 'AS65000',
				       peer_as => 'AS65002',
				       source_addr => '10.2.0.37',
				       peer_addr => '10.2.0.38'
				     );

my $list = renew Net::ACL( Type => 'prefix-list',
			   Name => 4 
			 );

my $config = $list->asconfig;

print $config;

