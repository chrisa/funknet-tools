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


package Funknet::Config::BGP;
use strict;
use Funknet::Config::Validate qw/ is_valid_os is_valid_as is_valid_router /;
use Funknet::Config::AccessList;    
use Funknet::Config::Neighbor;
use Funknet::Config::BGP::IOS;
use Funknet::Config::BGP::Zebra;

use base qw/ Funknet::Config /;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    my $l = Funknet::Config::ConfigFile->local;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'host')) {
	$self->warn("missing or invalid source");
	return undef;
    } else {
	$self->{_source} = $args{source};
    }

    unless (defined $args{local_as} && is_valid_as($args{local_as})) {
	$self->warn("missing or invalid local_as");
	return undef;
    } else {
        my $asno = $args{local_as};
        $asno =~ s/^AS//;
	$self->{_local_as} = $asno;
    }

    unless (defined $args{routes} && ref $args{routes} eq 'ARRAY') {
	$self->warn("no routes");
        $self->{_routes} = [];
    } else {
        $self->{_routes} = $args{routes}; 
    }

    $l->{router} eq 'ios' and 
	bless $self, 'Funknet::Config::BGP::IOS';
    $l->{router} eq 'zebra' and 
	bless $self, 'Funknet::Config::BGP::Zebra';

    return $self;
}

sub add_session {
    my ($self, %args) = @_;

    $args{remote_as} =~ s/^AS//;

    my $session = Funknet::Config::Neighbor->new( remote_as     => $args{remote_as},
						  remote_addr   => $args{remote_addr},
						  description   => $args{description},
						  soft_reconfig => $args{soft_reconfig},
						  source        => $self->{_source},
						  acl_in        => $args{acl_in},
						  acl_out       => $args{acl_out},
						);
    if (defined $session) {
	$self->{_neighbors}->{$args{remote_addr}} = $session;
    }
}

# accessors

sub source {
    my ($self) = @_;
    return $self->{_source};
}
sub local_as {
    my ($self) = @_;
    return $self->{_local_as};
}
sub routes {
    my ($self) = @_;
    return wantarray?@{$self->{_routes}}:$self->{_routes};
}
sub route_set {
    my ($self, $route) = @_;
    unless (defined $self->{_route_hash}) {
	for (@{$self->{_routes}}) {
	    $self->{_route_hash}->{$_} = 1;
	}
    }
    return 1
	if defined $self->{_route_hash}->{$route};
    return undef;
}
sub neighbors {
    my ($self) = @_;
    my @n = map { $self->{_neighbors}->{$_} } keys %{ $self->{_neighbors} };
    return @n;
}
sub neighbor_set {
    my ($self, $neighbor) = @_;
    return (defined $self->{_neighbors}->{$neighbor->remote_addr})?1:0;
}
sub neighbor {
    my ($self, $n) = @_;
    return $self->{_neighbors}->{$n->remote_addr};
}

1;
