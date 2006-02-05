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


package Funknet::Config::FirewallChain;
use strict;
use base qw/ Funknet::Config /;
use Funknet::Config::FirewallChain::IPTables;
use Funknet::Debug;

=head1 NAME

Funknet::Config::FirewallChain

=head1 DESCRIPTION

Provides a collection object for FirewallRules.

=head1 METHODS

# CHANGEME
=head2 new(source => 'whois', firewall => \@firewall_rules)

Takes the source and a listref of FirewallRules. 

=cut

sub new
{
    debug("arrived in FirewallChain new");
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    my $l = Funknet::ConfigFile::Tools->local;

    $self->{_type}	= $args{type};
    $self->{_rules}	= $args{rules};
    $self->{_create}	= $args{create};

    my $subtype;
    my $firewall_type = $l->{firewall_type};

    if ($firewall_type eq 'iptables') {
        $subtype = 'IPTables';
    }
    if ($firewall_type eq 'ipfw') {
        $subtype = 'IPFW';
    }

    my $full_object_name = "Funknet::Config::FirewallChain::$subtype";
    debug("my firewall type is $full_object_name");

    bless $self, $full_object_name;

    return($self);
}

sub firewall {
    my ($self) = @_;
    return @{$self->{_rules}};
}

sub needscreate {
    my ($self) = @_;
    return ($self->{_create});
}

sub type {
    my ($self) = @_;
    return ($self->{_type});
}

1;
