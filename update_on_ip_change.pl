#!/usr/pkg/bin/perl 

#
# Copyright (c) 2003
#       The funknet.org Group.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#       This product includes software developed by The funknet.org
#       Group and its contributors.
# 4. Neither the name of the Group nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE GROUP AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE GROUP OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


# Script to check for change of IP on given Interface
# compare to whois and update the whois if required.

# Requires arguments of interface to watch and the 
# name of the tunnel object to compare against.

use strict;
use Mail::GnuPG;
use MIME::Entity;
use Net::Interface;
use Socket;
use Getopt::Std;

use lib './lib';
use Funknet::Config;
use Funknet::Config::Whois;
use Funknet::Config::Validate qw/is_valid_as/;

use Data::Dumper;

my %opt;
getopts('f:i:', \%opt);
unless ($opt{f} && $opt{i}) {
    print STDERR "usage: $0 -f <path_to_funknet_config_file> -i <interface>\n";
    exit(1);
}

my $config = Funknet::Config::ConfigFile->new( $opt{f} );
my $nic = new Net::Interface($opt{i}) or die "whoopsy creating interface object";

my $addr= $nic->address;
my $ip_info = inet_ntoa($addr);

# if IP has changed, we need 1st to update the funknet.conf file
# as other bits use it 
if ($config->local_endpoint ne $ip_info)
{
	print STDERR "best update the funknet.conf\n";
	$config->local_endpoint($ip_info);
	$config->write();
}

my $update_email = $config->update_email;
my $key_id = $config->pgp_key_id;
my $pgp_passphrase = $config->pgp_passphrase;
my $pgp_key_dir = $config->pgp_key_dir;
my $signing_email = $config->signing_email;
my $from_email = $config->from_email;
my $local_as = $config->local_as;

my $hostname = qx[/bin/hostname];

my $whois = Funknet::Config::Whois->new;
unless (defined $whois)
{
	die "Error getting a Funknet::Config::Whois object\n";
}

my @tunnel_objects = $whois->my_tunnels;

unless (is_valid_as($local_as))
{
	print STDERR "invalid local_as : (format AS65xxx)\n";
	exit(1);
}

foreach my $tunnel_object (@tunnel_objects)
{
	my $old_ip;
	my $enc;
        my @endpoints = $tunnel_object->endpoint;
        my @encryptions = $tunnel_object->encryption;
        my @ass = $tunnel_object->as;
        my ($as1,$as2) = @ass;
        if ($as1 eq $local_as)
        {
                $old_ip = shift(@endpoints);
                my $tmp = shift(@endpoints);
                $enc = shift(@encryptions);
                print "ENDPOINT: $tmp\nSECURE: $enc\n";
        }
        elsif ($as2 eq $local_as)
        {
                my $tmp = shift(@endpoints);
                $old_ip = shift(@endpoints);
                $enc = shift(@encryptions);
                print "ENDPOINT: $tmp\nSECURE: $enc\n";
        }
	else
	{
		print STDERR "Error: Object $tunnel_object is not for $local_as\n";
		next;
	}

	chomp($ip_info);

	if($old_ip ne $ip_info)
	{
		print STDERR "IP changed from $old_ip to $ip_info\n";
		update_whois($old_ip, $ip_info, $tunnel_object);
	}
	else
	{
		print"IP same\n";
	}
}
exit(0);

sub update_whois
{
	my $old_ip = shift(@_);
	my $new_ip = shift(@_);
	my $current = shift(@_);
	print STDERR "updating whois to $new_ip\n";
	my @endpoints = $current->endpoint();
	for my $ip (@endpoints)
	{
		if ($ip eq $old_ip) { $ip = $new_ip; }
	}
	$current->endpoint(\@endpoints);
	$current->changed($signing_email);

	my $entry = $current->text();
	my $subject="IP Update from $hostname";
	chomp($subject);
	print"from:$from_email\nto:$update_email\nsubject:$subject\n";
	my $mime_obj = MIME::Entity->build(From    => $from_email,
					   To      => $update_email,
					   Subject => $subject,
					   Data    => [$entry]);
	my $mg = new Mail::GnuPG ( key => $key_id, 
				   passphrase => $pgp_passphrase,
				   keydir => $pgp_key_dir );
	my $ret = $mg->mime_sign($mime_obj, $signing_email);
	print"$ret\n";
	$mime_obj->smtpsend;
}

