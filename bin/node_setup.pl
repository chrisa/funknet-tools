#!/usr/local/bin/perl -w
use strict;
use Funknet::Whois::ObjectGenerator;

my $gen = Funknet::Whois::ObjectGenerator->new( source => 'FUNKNET' );
my $me = $gen->person( 'name'    => 'Me',
		       'address' => 'Some Where',
		       'e_mail'  => 'me@example.com',
		       'phone'   => '23785542312',
                       );

print scalar $me->text;

#my $gen = Funknet::Whois::ObjectGenerator->new( 'person' => 'ME1-FUNKNET' );
#my $me = $gen->mntner( 'admin_c' => 'ME1-FUNKNET',
#		       'tech_c'  => 'ME1-FUNKNET',
#		       'name     => 'MY-MUNTER',
#                       );
