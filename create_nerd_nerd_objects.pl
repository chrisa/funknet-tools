#!/usr/bin/perl -w

use strict;

use lib './lib';

use Funknet::Whois;
use Net::Whois::RIPE;
use Data::Dumper;

my @ass;
my @as_names;
my @done;
my %nerd_autnum_objects;
my %splurby_nerd_tunnels;
my %as_names;
my %as_nums;
my %endpoints;
my %nerd_tunnels;

my $whois = Net::Whois::RIPE->new( 'whois.funknet.org');
unless (defined $whois)
{ 
        die "Error getting a Funknet::Config::Whois object\n";
}

my $transobj = $whois->query('AS-FUNKTRANSIT');

@ass = $transobj->members;

$whois->type('aut-num');

foreach my $thing ($transobj->members)
{
	next if (($thing eq 'AS65000') or ($thing eq 'AS65023'));
	$whois->type('aut-num');
	my $reply = $whois->query($thing);
	$nerd_autnum_objects{$thing} = $reply;
	$as_names{$thing} = $reply->as_name;
	$as_nums{$reply->as_name} = $thing;
}

$whois->type('aut-num');
my $splurby_aut_num = $whois->query('AS65000');

foreach my $thing ($splurby_aut_num->tun)
{
		$whois->type('tunnel');
		my $tun = $whois->query($thing);
		$splurby_nerd_tunnels{$thing} = $tun;		
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
	}
	elsif ($as2  =~ /AS65000/m)
	{
		$ip = shift(@endpoints);
		$other_as = $as1;
	}
	$endpoints{$other_as} = $ip;
	print "$other_as:$ip\n";
}

my $ab='10.4.';
my $d=0;
my $c=0;
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
		my $this_d_local=$d+1;
		my $this_d_remote=$d+2;
		my $this_local="$ab$c\.$this_d_local";
		my $this_remote="$ab$c\.$this_d_remote";
		print FILE "address: $this_local\n";
		print FILE "address: $this_remote\n";
		print FILE "endpoint: $local_endpoint\n";
		print FILE "endpoint: $remote_endpoint\n";
		print FILE "admin-c: CA1-FUNKNET\n";
		print FILE "tech-c: CA1-FUNKNET\n";
		print FILE "mnt-by: FUNK-MNT\n";
		print FILE "notify: chris\@nodnol.org\n";
		print FILE "notify: dunc\@lemonia.org\n";
		print FILE "changed: dunc\@lemonia.org\n";
		print FILE "source: FUNKNET\n";
		print FILE "\n";

		push(@{$nerd_tunnels{$thing}},$tunnel_name);
		push(@{$nerd_tunnels{$twat}},$tunnel_name);

		push(@done,"$local_as_name:$remote_as_name");
		push(@done,"$remote_as_name:$local_as_name");
		if($d == 252)
		{
			$d=0;
			$c++;
		}
		else
		{
			$d+=4;
		}
	}
}
close(FILE);

open(FILE,">nerd_autnum_objects");
foreach my $nerd_aut_nums (keys(%nerd_autnum_objects))
{
	my $my_as_name = $as_names{$nerd_aut_nums};

	my @new_tunnels;	
	my @new_import;	
	my @new_export;	

	my @old_tunnels = $nerd_autnum_objects{$nerd_aut_nums}->tun;	
	my @old_import = $nerd_autnum_objects{$nerd_aut_nums}->ximport;	
	my @old_export = $nerd_autnum_objects{$nerd_aut_nums}->export;	

	foreach my $thing (@old_tunnels)
	{
		push(@new_tunnels,$thing);
	}
	foreach my $thing (@old_import)
	{
		push(@new_import,$thing);
	}
	foreach my $thing (@old_export)
	{
		push(@new_export,$thing);
	}
	foreach my $thing (@{$nerd_tunnels{$nerd_aut_nums}})
	{
		my $other_as;

		if($thing =~ /^$my_as_name/)
		{
			($other_as = $thing) =~ s/^$my_as_name-(.*)/$1/; 
		}
		else
		{
			($other_as = $thing) =~ s/(.*)-$my_as_name$/$1/;
		}
		
		push(@new_tunnels,$thing);
		my $new_imp = "from $as_nums{$other_as} action pref=100; accept $as_nums{$other_as} and NOT $nerd_aut_nums";
		my $new_exp = "to $as_nums{$other_as} announce $nerd_aut_nums";
		push(@new_import,$new_imp); 
		push(@new_export,$new_exp); 
	}

	$nerd_autnum_objects{$nerd_aut_nums}->tun(\@new_tunnels);
	$nerd_autnum_objects{$nerd_aut_nums}->export(\@new_export);
	$nerd_autnum_objects{$nerd_aut_nums}->ximport(\@new_import);
	
	my $text = $nerd_autnum_objects{$nerd_aut_nums}->text;
	print FILE "$text";
	print FILE "\n";
	print FILE "\n";
}

close(FILE);
exit(0);
