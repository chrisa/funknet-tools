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

package Funknet::Config::CLI;
use strict;
use Funknet::Config::CLI::Secrets;
use Funknet::Config::CLI::Zebra;
use Funknet::Config::CLI::IOS;
use Funknet::ConfigFile::Tools;

=head1 NAME

Funknet::Config::CLI

=head1 SYNOPSIS

    my $cli = Funknet::Config::CLI->new();
    @local_tun = $cli->get_interfaces;

    my $cli = Funknet::Config::CLI->new();
    my $bgp = $cli->get_bgp;

=head1 DESCRIPTION

This module is the base class for the router-specific methods for
retrieving data from the Zebra and IOS command-line interfaces. The
constructor returns an object containing all the information required
to connect to the router (address/username/passwords), blessed into
the appropriate class depending on the local_router config param.

=head1 METHODS

get_bgp and get_access_list are implemented in both IOS.pm and
Zebra.pm, but accessed through an object returned from the constructor
of this module.

=head2 get_bgp

This method retrieves the BGP configuration from the running
router. The data structure is returned as a hashref. The top level
data structure is Funknet::Config::BGP, which contains the routes
advertised (network statements) for this BGP router. (todo: add other
BGP configuration statements to this object - ebgp multihop etc.)

The BGP object contains a list of Neighbor objects, which represent
the currently configured sessions.

=head2 get_access_list

This method retrieves an access list from the router. It translates
the 'sho ip prefix-list $name' output into the config commands form
generated by RtConfig. (todo: this.)

=head2 get_as

Given an IP address, this method attempts to find the AS from the
local systems BGP table. Returns undef if it's not found. Untested on
IOS.

=head2 check_login

XXX stubbed out for now

A sort of internal method, but called from the constructor of
CLI.pm. Checks that the relevant authentication information is
available, including enable. (todo: argument to make enable password
optional?)

=head2 login / logout

Pair of subs to manage connections to the router CLI. login creates
the Net::Telnet object and stashes it. You should access this through
$obj->{t}. 

logout calls close on that, and also undefs it. login won't create a
new N::T object unless $self->{t} is undef, so do call logout...

FIXME: if login decides to reuse a N::T object have it do a 'ping' of
some sort to make sure it's still awake? 

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    my $l = Funknet::ConfigFile::Tools->local;

    $self->{_username} = Funknet::Config::CLI::Secrets->username( $l->{host} );

    $self->{_password} = Funknet::Config::CLI::Secrets->password( $l->{host} );
    $self->{_enable}   = Funknet::Config::CLI::Secrets->enable(   $l->{host} );
    
    # see if the caller wants a persistent connection to zebra 
    # (this is used by Funknet::Tools::Traceroute and probably
    # should be elsewhere).
    
    if ($args{Persist}) {
	$self->{_persist} = 1;
    }

    # see if the caller requested Debug. if so, the trace from Net::Telnet will 
    # show up on STDOUT.

    if ($args{Debug}) {
	$self->{_debug} = 1;
    }

    # rebless into relevant class
    # if we're Zebra, and host is localhost, then use vtysh (AF_UNIX)
    # else use Zebra (AF_INET). 

    $l->{router} eq 'ios' and 
	bless $self, 'Funknet::Config::CLI::IOS';
    if (defined $l->{bgpd_vty} && $l->{host} eq "127.0.0.1") {
	$l->{router} eq 'zebra' and 
	  bless $self, 'Funknet::Config::CLI::Zebra::Vtysh';
    } else {
	$l->{router} eq 'zebra' and 
	  bless $self, 'Funknet::Config::CLI::Zebra::Telnet';
    }

    # check we have the correct details or don't return the object.
    
    $self->check_login
	or return undef;

    return $self;
}

=head2 exec_cmd

Runs the specified command in user mode, and returns the text
(supports looking-glass functions). Doesn't do any checking of the
command itself, caller must do that.

=cut

sub exec_cmd {
    my ($self, $cmd) = @_;

    $self->login;
    my @output = $self->{t}->cmd($cmd);
    $self->logout;

    return wantarray ? @output : join '', @output;
}

1;
