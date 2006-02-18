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


package Funknet::Config;
use strict;

use Funknet::Debug;
use Funknet::Config::Whois;
use Funknet::Config::Host;
use Funknet::Config::CommandSet;
use Funknet::Config::SystemFileSet;
use Funknet::Config::ConfigSet;
use Funknet::ConfigFile;

=head1 NAME

Funknet::Config

=head1 ABSTRACT

The funknet-tools autoconfig system.

=head1 SYNOPSIS

    my $conf = new Funknet::Config( configfile => '/full/path/to/configfile' );

=head1 DESCRIPTION

    Reads and parses a Funknet config file

=head1 METHODS

=head2 new
=head2 diff
=head2 apply

=head1 FUNCTIONS

=head2 debug

=cut

use vars qw/ $VERSION /;
$VERSION = 0.9;

my (@warnings, @errors);

sub new {
    my ($class,%args) = @_;
    my $self = bless {}, $class;
    $self->{_error} = [];
    $self->{_warn} = [];
    $self->{_config} = Funknet::ConfigFile::Tools->new( $args{configfile}, $args{interactive} )
	or die "Couldn't load config file";
    return $self;
}


sub warn {
    my ($self, $errstr) = @_;
    if (defined $errstr) {
	push @warnings, $errstr;
	if (Funknet::ConfigFile::Tools->warnings) {
	    print STDERR "WARNING: $errstr\n";
	}
	return 1;
    } else {
	if (scalar @warnings) {
	    return wantarray?@warnings:join "\n", @warnings;
	} else {
	    return undef;
	}
    }
}

sub error {
    my ($self, $errstr) = @_;
    if (defined $errstr) {
	push @errors, $errstr;
	if (Funknet::ConfigFile::Tools->halt) {
	    die "STOP: $errstr";
	}
	return 1;
    } else {
	if (scalar @errors) {
	    return wantarray?@errors:join "\n", @errors;
	} else {
	    return undef;
	}
    }
}

sub bgp_diff {
    my ($self) = @_;
    
    my $whois = Funknet::Config::Whois->new();
    my $host = Funknet::Config::Host->new();

    my $whois_bgp = $whois->sessions;
    my $host_bgp = $host->sessions;
    
    my $diff = $whois_bgp->diff($host_bgp);
    return $diff;
}

sub tun_diff {
    my ($self) = @_;
    
    my $whois = Funknet::Config::Whois->new();
    my $host = Funknet::Config::Host->new();

    my $whois_tun = $whois->tunnels;
    my $host_tun = $host->tunnels;
    
    my $diff = $whois_tun->diff($host_tun);
    return ($diff, $whois_tun, $host_tun);
}

sub fwall_diff {
    my ($self, $tun_set, $enc_set) = @_;
    
    my $whois = Funknet::Config::Whois->new();
    my $host = Funknet::Config::Host->new();

    my $whois_fwall = $whois->firewall ($tun_set, $enc_set);
    my $host_fwall = $host->firewall($tun_set, $enc_set);
    
    my $diff = $whois_fwall->diff($host_fwall);
    return ($diff, $whois_fwall, $host_fwall);
}

sub enc_diff {
    my ($self, $whois_tun, $host_tun) = @_;
    
    my $whois = Funknet::Config::Whois->new();
    my $host = Funknet::Config::Host->new();

    my $whois_enc = $whois->encryption($whois_tun);
    my $host_enc = $host->encryption($host_tun);
    
    my $diff = $whois_enc->diff($host_enc);
    return ($diff, $whois_enc, $host_enc);
}

sub bgp_config {
    my ($self) = @_;
    
    my $whois = Funknet::Config::Whois->new();
    my $whois_bgp = $whois->sessions;
    
    my $config = $whois_bgp->config();
    return ($config, $whois_bgp);
}

sub tun_config {
    my ($self) = @_;

    my $whois = Funknet::Config::Whois->new();
    my $whois_tun = $whois->tunnels;

    my $config = $whois_tun->config();
    return ($config, $whois_tun);
}

sub fwall_config {
    my ($self, $tun_set, $enc_set) = @_;

    my $whois = Funknet::Config::Whois->new();
    my $whois_fwall = $whois->firewall($tun_set, $enc_set);

    my $config = $whois_fwall->config();
    return ($config, $whois_fwall);
}

sub enc_config {
    my ($self, $tun_set) = @_;

    my $whois = Funknet::Config::Whois->new();
    my $whois_enc = $whois->encryption($tun_set);

    my $config = $whois_enc->config();
    return ($config, $whois_enc);
}

1;
