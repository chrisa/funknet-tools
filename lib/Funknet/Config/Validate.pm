#!/usr/bin/perl -w
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


package Funknet::Config::Validate;
use strict;
use base qw/ Exporter /;
use vars qw/ @EXPORT_OK %EXPORT_TAGS /;

@EXPORT_OK = qw/ is_ipv4 is_ipv6 is_valid_type is_valid_as is_valid_firewall
                 is_valid_os is_valid_router is_valid_proto 
                 is_valid_ifname is_valid_encryption 
		 is_valid_filepath is_valid_ipsec_proto
		 is_valid_ipsec_keying is_valid_ipsec_cipher
		 is_valid_ipsec_hash is_valid_ipsec_dhgroup
		 is_valid_ipsec_ikemethod is_valid_ipsec_policy
		 /;

%EXPORT_TAGS = (
		ipsec => [ qw/  is_valid_ipsec_proto is_valid_ipsec_ikemethod
				is_valid_ipsec_keying is_valid_ipsec_cipher
				is_valid_ipsec_hash is_valid_ipsec_dhgroup 
				is_valid_ipsec_policy
				/ ],
	       );

sub is_ipv4 {
    my ($addr) = @_;
    if (defined($addr) &&
	$addr ne "" &&
	$addr =~ m/^\d+\.\d+\.\d+\.\d+$/ ) {
	for (split /\./, $addr ) {
	    return 0 if $_ < 0 or $_ > 255;
	}
	return 1;
    } else {
	return 0;
    }
}

sub is_ipv6 {
    my ($addr) = @_;
    return 1;
}

sub is_valid_type {
    my ($type) = @_;

    if ($type eq 'sit'  ||
	$type eq 'ipip' ||
	$type eq 'gre') {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_firewall {
    my ($type) = @_;

    if ($type eq 'iptables'  ||
	$type eq 'ipfw') {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_os {
    my ($os) = @_;

    if ($os eq 'linux'   ||
	$os eq 'bsd'     ||
	$os eq 'ios'     ||
	$os eq 'solaris' ) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_router {
    my ($router) = @_;

    if ($router eq 'zebra' ||
	$router eq 'ios'   ) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_as {
    my ($as) = @_;
    
    if ($as =~ /^AS\d+/) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_proto {
    my ($proto) = @_;
    
    if ($proto =~ /^[46]$/) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_ifname {
    my ($ifname) = @_;
    
    if ($ifname =~ /^[.a-zA-Z]+\d+$/) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_encryption {
    my ($os) = @_;

    if ($os eq 'ipsec'   ||
	$os eq 'openvpn' ) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_ipsec_proto {
    my ($proto) = @_;
    
    if ($proto eq 'esp' ||
	$proto eq 'ah'  ||
	$proto eq 'esp+ah' ) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_ipsec_keying {
    my ($keying) = @_;

    if ($keying eq 'ike' || 
	$keying eq 'manual' ) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_ipsec_policy {
    my ($policy) = @_;

    if ($policy eq 'ipip-trans' ||
	$policy eq 'unknown') {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_ipsec_cipher {
    my ($cipher_string) = @_;
    
    my @ciphers = split / /, $cipher_string;
    for my $cipher (@ciphers) {
	unless ($cipher eq 'aes' || 
		$cipher eq 'des' ||
		$cipher eq '3des' ) {
	    return 0;
	} 
    }
    return 1;
}

sub is_valid_ipsec_hash {
    my ($hash_string) = @_;
    
    my @hashs = split / /, $hash_string;
    for my $hash (@hashs) {
	unless ($hash eq 'md5'       || 
		$hash eq 'sha'       ||
		$hash eq 'hmac_sha1' ||
		$hash eq 'hmac_md5' ) {
	    return 0;
	} 
    }
    return 1;
}

sub is_valid_ipsec_dhgroup {
    my ($dhgroup) = @_;

    if ($dhgroup eq '1' || 
	$dhgroup eq '2' ||
	$dhgroup eq '5' ||
	$dhgroup eq 'nopfs' ) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_ipsec_ikemethod {
    my ($method) = @_;

    if ($method eq 'secret' ||
	$method eq 'cert' ) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_filepath {
    # later...
    return 1;
}

      
	
1;
