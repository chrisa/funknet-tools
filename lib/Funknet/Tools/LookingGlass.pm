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


package Funknet::Tools::LookingGlass;
use strict;

=head1 DESCRIPTION

Functions to implement a Looking Glass - just BGP etc, look elsewhere
in this tree for Ping and Traceroute.

=cut

use Funknet::Config::ConfigFile;
use Funknet::Config::CLI;
use Funknet::Config::Validate qw/ is_ipv4 /;

=head1 METHODS

=head2 new

Pass 'configfile => funknet.conf for the router you want to connect to'.

=head2 sho_ip_bgp

call with either an ipv4 address, an aspath regex or the empty string.

=head2 sho_ip_bgp_sum

=head2 sho_ver

=cut

our $cf;

sub new {
    my ($class, %args) = @_;

    unless (defined $args{configfile} && -f $args{configfile}) {
	warn "can't access configfile: $args{configfile}";
	return undef;
    }
    unless (defined $cf) {
	$cf = Funknet::Config::ConfigFile->new($args{configfile})
	  or return undef;    
    }

    my $self = bless {}, $class;
    $self->{_cli} = Funknet::Config::CLI->new();

    return $self;
}

sub DESTROY {
    my ($self) = @_;
    if (defined $self->{t}) {
	$self->{t}->logout;
    }
}

sub sho_ip_bgp {
    my ($self, $string) = @_;
    return undef unless defined $string;

    # string can be an ipv4 address, an aspath regex or the empty string
    if (is_ipv4($string) || 
	$string =~ /^r(egexp)? [0-9\^\$_ ]+$/ ||
	$string eq '') {
	
	my $text = $self->{_cli}->exec_cmd("sho ip bgp $string");
	return $text;
    } else {
	warn "invalid string passed to sho_ip_bgp: $string";
    }
}

sub sho_ip_bgp_sum {
    my ($self) = @_;

    my $text = $self->{_cli}->exec_cmd("sho ip bgp sum");
    return $text;
}

sub sho_ver {
    my ($self) = @_;

    my $text = $self->{_cli}->exec_cmd("sho ver");
    return $text;
}

1;
