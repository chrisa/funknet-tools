#!/usr/bin/perl

# Script to check for change of IP on given Interface
# compare to whois and update the whois if required.

# Requires arguments of interface to watch and the 
# name of the tunnel object to compare against.

use strict;
use Net::Whois::RIPE;
use Mail::GnuPG;
use MIME::Entity;

unless (scalar @ARGV == 2) 
{
	print STDERR "usage: $0 <interface> <tunnel_name>\n";
	exit(1);
}

my $update_email='auto-dbm@funknet.org';
my $key_id='5CDA2963';
my $signing_email='funknet@vogon.braddon.org.uk';
my $key_passphrase='';

my $hostname = qx[/bin/hostname];

my $iface = $ARGV[0];
my $tunnel_object = $ARGV[1];

my $old_ip = get_ip_from_whois($tunnel_object);
my $ip_info = get_ip($iface);
chomp($ip_info);

if($old_ip ne $ip_info)
{
	print"IP changed from $old_ip to $ip_info\n";
	update_whois($ip_info);
}
else
{
	print"IP same\n";
}

exit(0);

sub get_ip_from_whois
{
	my $tunnel_object = shift(@_);

	my $whois = Net::Whois::RIPE->new('whois.funknet.org') || die "cant connect to whois";

	$whois->no_recursive;
	$whois->source('FUNKNET');
	$whois->type('tunnel');

	my $tun = $whois->query($tunnel_object);
	my @endpoints = $tun->endpoint;
	my $ip = shift(@endpoints);
	chomp($ip);
	return($ip);
}

sub read_file
{
	open(FILE,'current_ip');
	my $old_ip = <FILE>;
	close(FILE);
	return($old_ip);
}

sub write_file
{
	my $new_ip = shift(@_);
	open(FILE,'>current_ip') || die "couldn't write to IP cache file";
	print(FILE "$new_ip");
	close(FILE);
}

sub get_ip
{
	my $iface = shift(@_);

	#This bit is shit, but nice module wouldn't build
	my $ip = qx[/sbin/ifconfig $iface 2> /dev/null | /bin/grep inet | /bin/grep -v inet6] || die "couldn't get settings of interface $iface";
	$ip =~ s/.*inet[^\d]+([^\ ]+).*/$1/;
	return($ip);
}

sub update_whois
{
	my $new_ip = shift(@_);
	print "updating whois to $new_ip\n";
	my $subject="IP update from $hostname";
	my @current_entry = get_entry_from_whois();
	foreach my $thing (@current_entry)
	{
		$thing =~ s/$old_ip/$new_ip/;
		$thing =~ s/changed:\s+.+@.+\s+\d+/changed: $signing_email/; 
		$thing =~ s/^%.*//;
		print "$thing\n";
		$thing =~ s/^(.*)$/$1\n/;
	}
	my $ref_to_msg = \@current_entry;
	my $mime_obj = MIME::Entity->build(From    => $signing_email,
					   To      => $update_email,
					   Subject => $subject,
					   Data    => $ref_to_msg);
	print"$signing_email\n$update_email\n$subject\n$ref_to_msg\n$key_id\n";
	my $mg = new Mail::GnuPG ( key => $key_id, 
				   passphrase => $key_passphrase,
				   keydir => '/home/funknet/.gnupg' );
	my $ret = $mg->mime_sign($mime_obj, $signing_email);
	print"$ret\n";
	$mime_obj->smtpsend;
}

sub get_entry_from_whois
{
	my $whois = Net::Whois::RIPE->new('whois.funknet.org') || die "cant connect to whois";

	my @current;
	my $test;

	$whois->no_recursive;
	$whois->source('FUNKNET');
	my $iterator = $whois->query_iterator($tunnel_object);
	while (my $obj = $iterator->next) 
	{
		$test = $obj->content;
	}
	@current=split('\n',$test);
	return(@current);
}
