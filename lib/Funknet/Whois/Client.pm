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
	$query_string = "-t $self->{_type} -i $self->{_inverse} $query";
	$self->{_inverse} = '';
    } else {
	$query_string = "-t $self->{_type} $query";
    }

    $self->_connect();
    my $s = $self->{_socket};
    print $s "$query_string\n";
    
    my @objects = $self->parse_result();
    return wantarray ? @objects : $objects[0];
}

sub inverse_lookup {
    my ($self, $type) = @_;
    $self->{_inverse} = $type;
}

sub parse_result {
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
    
1;
