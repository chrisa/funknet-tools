#!/usr/pkg/bin/perl -w

use strict;

use lib './lib';

use Net::Whois::RIPE;
use Data::Dumper;

my @ass;
my @as_names;
my @done;
my %nerd_autnum_objects;
my %splurby_nerd_tunnels;
my %as_names;
my %endpoints;

my $whois = Net::Whois::RIPE->new( 'whois.funknet.org');
unless (defined $whois)
{ 
        die "Error getting a Funknet::Config::Whois object\n";
}


#$whois->source('FUNKNET');
#$whois->type('aut-num');

my $transobj = $whois->query('AS-FUNKTRANSIT');

my $trans_text = $transobj->text();

my @lines = split('\n',$trans_text);

foreach my $thing (@lines)
{
	if($thing =~ /^members:/)
	{
		
		$thing =~ s/[^A]+(AS\d\d\d\d\d)/$1/;
		push (@ass,$thing);
	}
}

$whois->type('aut-num');

foreach my $thing (@ass)
{
	next if (($thing eq 'AS65000') or ($thing eq 'AS65023'));
	$whois->type('aut-num');
	my $reply = $whois->query($thing);
	my $text = $reply->text;
	@lines = split('\n',$text);
	foreach my $bitch (@lines)
	{
        	if($bitch =~ /^as-name:/)
        	{
			$bitch =~ s/as-name: (.*)/$1/;
			$whois->type('tunnel');
			$as_names{$thing} = $bitch;
        	}
	}
}

$whois->type('aut-num');
my $splurby_aut_num = $whois->query('AS65000');
my $splurby_aut_text = $splurby_aut_num->text();
@lines = split('\n',$splurby_aut_text);

foreach my $thing (@lines)
{
        if($thing =~ /^tun:/)
        {
		$thing =~ s/tun: (.*)/$1/;
		$whois->type('tunnel');
		my $tun = $whois->query($thing);
		$splurby_nerd_tunnels{$thing} = $tun;		
        }
}

foreach my $splurby_tun (keys(%splurby_nerd_tunnels))
{
	my @endpoints = $splurby_nerd_tunnels{$splurby_tun}->endpoint;
	my @ass = $splurby_nerd_tunnels{$splurby_tun}->as;
	my $ip;
	my $other_as;
	my $splurby_as='AS65000';
        my ($as1,$as2) = @ass;
	if ($as1 =~ /AS65000/m)
	{ 
		my $tmp = shift(@endpoints);
		$ip = shift(@endpoints);
		$other_as = $as2;
		print STDERR "as1 matched\n";
	}
	elsif ($as2  =~ /AS65000/m)
	{
		$ip = shift(@endpoints);
		$other_as = $as1;
		print STDERR "as2 matched\n";
	}
	$endpoints{$other_as} = $ip;
	print "$other_as:$ip\n";
}

open(FILE,">nerd_nerd_objects");
print STDERR "bout to start big loop\n";
foreach my $thing (@ass)
{
	print Dumper $thing;
	next if (($thing eq 'AS65000') or ($thing eq 'AS65023'));

	foreach my $twat (@ass)
	{
		next if $twat eq $thing;
		next if(($twat eq 'AS65000') or ($twat eq 'AS65023'));

		next if(grep(/$as_names{$twat}:$as_names{$thing}/,@done));

		my $local_as_name = $as_names{$thing};
		my $remote_as_name = $as_names{$twat};
		my $tunnel_name = "$local_as_name-$remote_as_name";
		print STDERR "$as_names{$thing} <-> $as_names{$twat}\n";
		print STDERR "$tunnel_name\n";
		my $remote_endpoint = $endpoints{$twat};
		my $local_endpoint = $endpoints{$thing};

		print FILE "tunnel: $tunnel_name\n";
		print FILE "type: ipip\n";
		print FILE "as: $thing\n";
		print FILE "as: $twat\n";
		print FILE "address: \n";
		print FILE "address: \n";
		print FILE "endpoint: $local_endpoint\n";
		print FILE "endpoint: $remote_endpoint\n";
#		print FILE "endpoint: \n";
#		print FILE "endpoint: \n";
		print FILE "admin-c: CA1-FUNKNET\n";
		print FILE "tech-c: CA1-FUNKNET\n";
		print FILE "mnt-by: FUNK-MNT\n";
		print FILE "notify: chris\@nodnol.org\n";
		print FILE "changed: dunc\@lemonia.org\n";
		print FILE "source: FUNKNET\n";
		print FILE "\n";


		push(@done,"$local_as_name:$remote_as_name");
		push(@done,"$remote_as_name:$local_as_name");
	}
}
close(FILE);
exit(0);

sub get_endpoint
{
	print STDERR "Got called\n";
	my $as = shift (@_);
	my $as_name = shift (@_);

	my $ip;

	foreach my $guess (keys(%splurby_nerd_tunnels))
	{
		my $guess1 = "SPLURBY-$as_name";
		my $guess2 = "$as_name-SPLURBY";
		next unless (($guess eq $guess1) || ($guess eq $guess2));
		print STDERR "$guess\n";
exit(0);
		my $tunnel_object = $splurby_nerd_tunnels{$guess};
		my @ass = $tunnel_object->as;
		my @endpoints = $tunnel_object->endpoint;
	        my ($as1,$as2) = @ass;
		if ($as1 eq $as)
		{ 
			$ip = shift(@endpoints);
		}
		elsif ($as2 eq $as)
		{
			my $tmp = shift(@endpoints);
			$ip = shift(@endpoints);
		}
		else
		{
			print STDERR "error $tunnel_object not for $guess\n";
			next;
		}
	}
	print STDERR "whoops\n";
	return($ip);
}
