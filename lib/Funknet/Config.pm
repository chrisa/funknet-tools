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

use vars qw/ @EXPORT @ISA $DEBUG /;
use base qw/ Exporter /;
@EXPORT = qw/ $DEBUG &debug /;
$DEBUG = 0;

use Funknet::Config::Whois;
use Funknet::Config::Host;
use Funknet::Config::CommandSet;
use Funknet::Config::ConfigFile;

=head1 NAME

Funknet::Config

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

my (@warnings, @errors);

sub new {
    my ($class,%args) = @_;
    my $self = bless {}, $class;
    $self->{_error} = [];
    $self->{_warn} = [];
    $self->{_config} = Funknet::Config::ConfigFile->new( $args{configfile} )
	or die "Couldn't load config file";
    return $self;
}


sub warn {
    my ($self, $errstr) = @_;
    if (defined $errstr) {
	push @warnings, $errstr;
	if (Funknet::Config::ConfigFile->warnings) {
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
	if (Funknet::Config::ConfigFile->halt) {
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

    debug("Creating BGP session from whois data");
    my $whois_bgp = $whois->sessions;
    debug("Creating BGP session from host data");
    my $host_bgp = $host->sessions;
    
    my $diff = Funknet::Config::CommandSet->new( cmds => [ $whois_bgp->diff($host_bgp) ],
					         target => 'cli',
					       );
    return $diff;
}

sub tun_diff {
    my ($self) = @_;
    my $l = Funknet::Config::ConfigFile->local;
    
    my $whois = Funknet::Config::Whois->new();
    my $host = Funknet::Config::Host->new();
    my $whois_tun = $whois->tunnels;
    my $host_tun = $host->tunnels;
    
    my $diff;
    if ($l->{os} eq 'ios') {
	$diff = Funknet::Config::CommandSet->new( cmds => [ $whois_tun->diff($host_tun) ],
						  target => 'cli',
						);
    } else {
	$diff = Funknet::Config::CommandSet->new( cmds => [ $whois_tun->diff($host_tun) ],
						  target => 'host',
						);
    }
    return $diff;
}

sub debug {

    my $msg = shift;

    if ($DEBUG) {
	print STDERR "FUNKNET: $msg\n";
    }

}

1;
