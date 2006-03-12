# Copyright (c) 2005
#      The funknet.org Group.
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

=head1 NAME

Funknet::Whois::ObjectFile

=head1 DESCRIPTION

Implements a crappy database of whois objects. 

=cut

package Funknet::Whois::ObjectFile;
use strict;
use FileHandle;
use Fcntl qw/ :DEFAULT :flock :seek /;
use Funknet::Debug;
use Funknet::Whois::Object;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    $self->{_filename}  = $args{filename};
    $self->{_source}    = $args{source};
    $self->{_timestamp} = $args{timestamp};
    $self->{_fh}        = new FileHandle;

    return $self;
}

sub load {
    my ($self) = @_;
    my $fh = $self->{_fh};

    unless ($fh->open($self->{_filename})) {
        debug("no file $self->{_filename}");
        return;
    }

    my $objects_text;
    while (my $line = <$fh>) {
        next if $line =~ /^#/;
        $objects_text .= $line;
    }

    my @objects;
  OBJECT:
    for my $text (split /\r?\n\r?\n/, $objects_text) {
	if (my $object = Funknet::Whois::Object->new($text, TimeStamp => $self->{_timestamp})) {
            next OBJECT unless $object->source eq $self->{_source};
            push @objects, $object;
        }
    }
    $fh->close();

    $self->{_objects} = \@objects;
    return scalar @objects;
}

sub objects {
    my ($self) = @_;
    if (defined $self->{_objects}) {
        return @{$self->{_objects}};
    }
    return;
}

sub object_dump {
    my ($self, $objects) = @_;
    
    my $text;
    for my $type (keys %$objects) {
        for my $name (keys %{$objects->{$type}}) {
            $text .= scalar $objects->{$type}->{$name}->text();
            $text .= "\n";
        }
    }
    return $text;
}
    
sub save {
    my ($self, $objects) = @_;
    
    unless (scalar keys %$objects) {
        debug("no objects, not saving");
        return;
    }

    my $fh = $self->{_fh};
    
    if (-f $self->{_filename}) {
        unless ($fh->open($self->{_filename}, O_RDWR|O_TRUNC)) {
            warn "couldn't open $self->{_objfile} for read/write: $!";
            return undef;
        }
    }
    else {
        unless ($fh->open($self->{_filename}, O_RDWR|O_CREAT)) {
            warn "couldn't create $self->{_objfile} for read/write: $!";
            return undef;
        }
    }

    unless (flock $fh, LOCK_EX|LOCK_NB) {
	warn "couldn't lock $self->{_objfile}: $!";
	return undef;
    }
    unless($fh->seek(0, SEEK_SET)) {
	warn "couldn't seek: $!";
	return undef;
    }

    print $fh $self->object_dump($objects);

    flock ($fh, LOCK_UN);
    $fh->close();
}


1;
