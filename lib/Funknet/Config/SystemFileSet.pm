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

package Funknet::Config::SystemFileSet;
use strict;
use base qw/ Funknet::Config /;
use Funknet::Config::Root;
use Funknet::ConfigFile::Tools;
use Data::Dumper;

=head1 NAME

Funknet::Config::SystemFileSet

=head1 DESCRIPTION

A class to hold a list of SystemFile objects, and arrange for them to
get written out as root.

=head1 CONSTRUCTOR

Pass in the list of SystemFile objects.

=head1 as_text

Returns the list of files, with a line describing where they should
be written. For notifying proposed changes. XXX - get diffs here, somehow?

=head1 apply

Write out the list of files. XXX -- needs to gain root properly, not
expect to be run as root.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    if (defined $args{files} && ref $args{files} eq 'ARRAY') {
	foreach my $f (@{ $args{files} }) {
	    if (defined $f) {
		push @{ $self->{_files} }, $f;
	    }
	}
	return $self;
    } 
    $self->warn("no files specified in SystemFileSet->new");
    return undef;
}

sub add {
    my ($self, @files) = @_;
    push @{ $self->{_files} }, @_;
}

sub files {
    my ($self) = @_;
    return @{ $self->{_files} };
}

sub as_text {
     my ($self) = @_;
     defined $self->{_files} or return undef;
     my $l = Funknet::ConfigFile::Tools->local;
     my $text = '';
     if (scalar grep { defined $_ } @{ $self->{_files} }) {
          my @deletes = grep { $_->is_delete() }  @{ $self->{_files} };
          my @writes  = grep { !$_->is_delete() } @{ $self->{_files} };

          for my $file (@deletes, @writes) {
               $text .= $file->as_text();
          }
          return $text;
     }
     else {
          return '';
     }
}

sub apply {
     my ($self) = @_;
     defined $self->{_files} or return undef;
    
     if (scalar @{ $self->{_files} }) {
          my @deletes = grep { $_->is_delete() }  @{ $self->{_files} };
          my @writes  = grep { !$_->is_delete() } @{ $self->{_files} };

          for my $file (@deletes, @writes) {
               $file->write;
          }
     } else {
          $self->warn("no files to apply in SystemFileSet->apply");
          return undef;
     }
}

sub diff {
    my ($self) = @_;
    defined $self->{_files} or return undef;
    my $difftext;
    if (scalar @{ $self->{_files} }) {
	for my $file (@{ $self->{_files} }) {
	    $difftext .= '=' x 80;
	    $difftext .= "\n".($file->path).":\n";
	    $difftext .= $file->diff;
	    $difftext .= '=' x 80;
	    $difftext .= "\n\n";
	}
	return $difftext;
    } else {
	$self->warn("no files to diff in SystemFileSet->diff");
	return undef;
    }
}    

1;
