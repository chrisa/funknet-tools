# Copyright (c) 2005
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

package Funknet::Whois::Client;
use strict;
use IO::Socket::INET;
use Data::Dumper;
use Funknet::Whois::Object;

our $cache;

=head1 NAME

Funknet::Whois::Client

=head1 DESCRIPTION

A library for doing whois lookups. Similar interface to
Net::Whois::RIPE. Caches found objects for the lifetime of the client
object. 

=head1 SYNOPSIS

    my $client = Funknet::Whois::Client->new('whois.funknet.org',
                                             Timeout => 10, 
                                             Port    => 4343);
    $client->source('FUNKNET');

    $client->type('aut-num');
    my $as = $w->query('AS65000');

    $client->type('route');
    $client->inverse_lookup('origin');
    my @routes = $client->query('AS65017');

=head1 METHODS

=head2 new ( $whois_host, ... )

Returns an instance of the client object. First argument is the
hostname, and defaults for Timeout and Port may be overridden with
named parameters. 

Does not immediately connect, see C<query>.

=head2 source ( $whois_source )

Set or query the whois source for this client object. 

=head2 type ( $object_type )

Set or query the current type of whois-object being queried for by
this client object.

=head2 query ( $query_string )

Make a query using the current type, inverse and source settings of
this client object. In scalar context returns the first object, and
returns all objects in array context.

Uses the query cache; the client object caches all whois-objects
retrieved until it is destroyed.

Connections are made lazily; if the connection fails, this method will
die.

Objects are returned as instances of Funknet::Whois::Object. 

=head2 inverse_lookup ( $lookup_key )

Set the inverse-lookup key to be used by this client object. This
stays in effect for the next call to query only. 

=head2 check_auth ( $object, $keyid )

A utility method for testing authentication of PGP keys against
objects. Returns true if $object can be updated by $keyid. 

=cut

sub new {
    my ($class, $host, %args) = @_;
    my $self = bless {}, $class;
    
    $self->{_host}    = $host;
    $self->{_port}    = $args{Port}    || 43;
    $self->{_timeout} = $args{Timeout} || 10;

    $self->{_cache} = {};
    return $self;
}

sub source {
    my ($self, $source) = @_;
    if (defined $source) {
	$self->{_source} = $source;
    }
    return $self->{_source};
}

sub type {
    my ($self, $type) = @_;
    if (defined $type) {
	$self->{_type} = $type;
    }
    return $self->{_type};
}
   
sub query {
    my ($self, $query) = @_;

    my $query_string;
    if ($self->{_inverse}) {
	if (defined $cache->{$self->{_type}}->{$self->{_inverse}}->{$query}) {
	    my @objects = @{ $cache->{$self->{_type}}->{$self->{_inverse}}->{$query} };
	    return wantarray ? @objects : $objects[0];
	} else {
	    $query_string = "-t $self->{_type} -i $self->{_inverse} $query";
	}
    } else {
	if (defined $cache->{$self->{_type}}->{$query}) {
	    my @objects = @{ $cache->{$self->{_type}}->{$query} };
	    return wantarray ? @objects : $objects[0];
	} else {
	    $query_string = "-t $self->{_type} $query";
	}
    }

    unless ($self->_connect()) {
        die "no connection";
    }
    my $s = $self->{_socket};
    print $s "$query_string\n";
    
    my @objects = $self->_parse_result();

    if ($self->{_inverse}) {
	$cache->{$self->{_type}}->{$self->{_inverse}}->{$query} = [ @objects ];
	$self->{_inverse} = '';
    } else {
	$cache->{$self->{_type}}->{$query} = [ @objects ];
    }

    return wantarray ? @objects : $objects[0];
}

sub inverse_lookup {
    my ($self, $type) = @_;
    $self->{_inverse} = $type;
}

sub _parse_result {
    my ($self) = @_;
    my $s = $self->{_socket};

    my @objects;
    my $obj_text = "";
    while (my $line = <$s>) {
	chomp $line;
	next if $line =~ /^%/;

	if ($line) {
	    $obj_text .= "$line\n";
	} else {
	    if ($obj_text) {
		my $obj = Funknet::Whois::Object->new($obj_text);
		if (defined $obj && $obj->object_type eq $self->{_type}) {
		    push @objects, $obj;
		}
		$obj_text = "";
	    }
	}
    }
    return @objects;
}

sub _connect {
    my ($self) = @_;
    $self->{_socket} = IO::Socket::INET->new(
					     PeerAddr => $self->{_host},
					     PeerPort => $self->{_port},
					     Proto    => 'tcp',
					     Type     => SOCK_STREAM,
					     Timeout  => $self->{_timeout},
					    );
    unless (defined $self->{_socket}) {
	return undef;
    }
}

sub check_auth {
    my ($self, $object, $keyid) = @_;
    my $auth_ok;

    $self->type('mntner');

  MNTNER:
    for my $mnt_by ($object->mnt_by) {
	my $mntner = $self->query($mnt_by);
        next MNTNER unless defined $mntner;
        for my $auth ($mntner->auth) {
            if ($auth eq "PGPKEY-$keyid") {
                $auth_ok = 1;
                last MNTNER;
            }
        }
    }
    return $auth_ok;
}


    
1;
