#!/usr/local/bin/perl -w
use strict;
use Funknet::Whois::ObjectGenerator;

# get a blank generator object, and make an unmaintained person. 

my $gen = Funknet::Whois::ObjectGenerator->new( source => 'FUNKNET' );
my $me = $gen->person( 'name'    => 'Me',
		       'address' => [ 'Some', 'Where' ],
		       'e_mail'  => 'me@example.com',
		       'phone'   => '23785542312',
                       );

print scalar $me->text;

# get a generator with that person, and make a maintainer. 

my $gen = Funknet::Whois::ObjectGenerator->new('source' => 'FUNKNET', 
					       'person' => 'CA1-FUNKNET' );

my $me = $gen->mntner( 'name'    => 'MY-MUNTER', 'auth' => 'PGPKEY-B355A313',
		       'descr'   => 'test munter', 'e_mail' => 'foo@bar.com' );

print scalar $me->text;
