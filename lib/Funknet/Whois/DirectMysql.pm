#
# $Id$
#
# Copyright (c) 2003
#	The funknet.org Group.
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
#	This product includes software developed by The funknet.org
#	Group and its contributors.
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

package Funknet::Whois::DirectMysql;
use strict;
use DBI;
use base qw/ DBI::db /;
use Funknet::Config::Validate qw/ is_ipv4 /;

=head1 NAME

Funknet::Whois::DirectMysql

=head1 DESCRIPTION

Provides a DBI object connected to the whois db's mysql database.

=head1 METHODS

=head2 new

Call with no params, returns a $dbh.

=cut

sub new {

    # get connection params from whois config file

    my $config;
    if (defined $ENV{WHOISD_CONFIG}) {
	$config = $ENV{WHOISD_CONFIG};
    } else {
	$config = '/usr/local/whoisd-funknet/conf/rip.config.FUNKNET';
    }
    
    my ($host, $port, $user, $pass, $name);
    open CONF, $config
      or die "couldn't open whoisd config file $config: $!";
    while (<CONF>) {
	next unless /^UPDSOURCE FUNKNET (.*),(.*),(.*),(.*),(.*) /;
	($host, $port, $user, $pass, $name) = ($1, $2, $3, $4, $5);
	last;
    }
    close CONF;
    
    unless (defined $host &&
	    defined $port &&
	    defined $user &&
	    defined $pass &&
            defined $name) {
	die "failed to get database params";
    }
    
    # connect to database

    my $dbh = DBI->connect("DBI:mysql:database=$name;host=$host;port=$port",$user,$pass);
    unless ($dbh) {
	die "failed to connect to $name: $DBI::errstr";
    }

    bless $dbh, "Funknet::Whois::DirectMysql";
    return $dbh;
}


sub ipv4_to_int {
    my ($self, $ipv4) = @_;
    unless (ref $self) {
        $ipv4 = $self;
    }

    unless (is_ipv4($ipv4) && $ipv4 =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/) {
	return undef;
    } else {
	return ((256 * 256 * 256 * $1) + (256 * 256 * $2) + (256 * $3) + $4);
    }
}

sub int_to_ipv4 {
    my ($self, $int) = @_;
    unless (ref $self) {
        $int = $self;
    }

    
    unless ($int >= 0 && $int <= 256**4) {
	return undef;
    } else {
	my $oct1 = int($int / (256 * 256 * 256));
	$int -= ($oct1 * 256 * 256 * 256);
	my $oct2 = int($int / (256 * 256));
	$int -= ($oct2 * 256 * 256);
	my $oct3 = int($int / 256);
	$int -= ($oct3 * 256);
	my $oct4 = $int;

	return "$oct1.$oct2.$oct3.$oct4";
    }
}


1;
