# Copyright (c) 2004
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


package Funknet::Config::EncryptionSet;
use strict;
use base qw/ Funknet::Config /;
use Funknet::Config::ConfigFile;
use Data::Dumper;

=head1 NAME

Funknet::Config::EncryptionSet

=head1 DESCRIPTION

Provides a collection object for Encryption objects. Contains the
->diff method for encryption.

=head1 METHODS

=head2 new(source => 'whois', encryption => \@encs)

Takes the source and a listref of Encryption objects. 

=head2 diff($hostobj)

Called on an EncryptionSet object of source whois and passed an
EncryptionSet object of source host, returns the commands required to
update the host's encryption config to that specified in the whois.

=head1 TODO

It should probably be possible to add Encryption objects via a method,
rather than all at once by passing the constructor a listref.

If we destroy interfaces, we should probably reuse the numbering.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    $self->{_encryptions} = $args{encryptions};
    $self->{_source} = $args{source};
    
    return $self;
}

sub encryptions {
    my ($self) = @_;
    return @{$self->{_encryptions}};
}

sub config {
    my ($self) = @_;
    my @config;

    for my $enc ($self->encryptions) {
	push @config, $enc->apply();
    }
    return @config;
}

sub source {
    my ($self) = @_;
    return $self->{_source};
}

=head2 diff



=cut

sub diff {
    my ($whois, $host) = @_;

    my (@cmds, $if_num);
    $if_num = 0;
    
    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
 	$whois->warn("Encryption diff passed objects backwards");
 	return undef;
    }    

    # create hashes of which peers are referenced by whois and host.
    my ($host_peers, $whois_peers);
    for my $enc (@{ $whois->{_encryptions} }) {
	$whois_peers->{$enc->peer} = $enc;
    }
    for my $enc (@{ $host->{_encryptions} }) {
	$host_peers->{$enc->peer} = $enc;
    }    

    my @diff = ();

    # walk the whois config, diffing or applying depending on 
    # whether the host config for this peer already exists
    for my $enc (@{ $whois->{_encryptions} }) {
	if (defined $host_peers->{$enc->peer}) {
	    my @result = $enc->diff($host_peers->{$enc->peer});
	    if (@result) {
		push @diff, @result;
	    }
	} else {
	    my @result = $enc->apply;
	    if (@result) {
		push @diff, @result;
	    }
	}
    }

    # walk the host config, unapplying where the peer config is 
    # no longer in whois. 
    for my $enc (@{ $host->{_encryptions} }) {
	if (!defined $whois_peers->{$enc->peer}) {
	    my @result = $enc->unapply;
	    if (@result) {
		push @diff, @result;
	    }
	}
    }

    return @diff;
}

1;
