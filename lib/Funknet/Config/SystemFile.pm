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


package Funknet::Config::SystemFile;
use strict;
use base qw/ Funknet::Config /;
use Funknet::Config::Root;
use Funknet::Config::Validate qw/ is_valid_filepath /;
use Text::Diff ();

=head1 NAME

Funknet::Config::SystemFile

=head1 DESCRIPTION


=head1 CONSTRUCTOR


=head2 text

Returns the list of commands, with a line describing where they should
be executed. For notifying proposed changes. If called with text,
replaces existing file contents.

=head2 path

Sets or gets the file path. 

=head2 write

Writes out the current file contents to the path specified.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    
    unless (defined $args{path} && is_valid_filepath($args{path})) {
	$self->warn("no path specified in SystemFile");
	return undef;
    } else {
	$self->{_path} = $args{path};
    }
    
    if (defined $args{text}) {
	$self->{_text} = $args{text};
    }
    
    # see if the file currently exists. if it does, grab 
    # a copy of it so we can do diffs later.

    if ( -f $self->{_path} ) {
	if (open FILE, $self->{_path}) {
	    local $/ = undef;
	    $self->{_old} = <FILE>;
	} else {
	    $self->warn("old file $self->{_path} exists but could not be read");
	}
    }
	    
    return $self;
}

sub path {
    my ($self, $path) = @_;
    
    if (defined $path) {
	$self->{_path} = $path;
    }
    return $self->{_path};
}

sub new_text {
    my ($self, $text) = @_;
    if (defined $text) {
	$self->{_text} = $text;
    }
    return $self->{_text};
}

sub old_text {
    my ($self) = @_;
    return $self->{_old};
}

sub write {
    my ($self) = @_;

    if (defined $self->{_delete}) {
	if (! unlink $self->{_path}) {
	    $self->warn("failed to unlink $self->{_path}: $!");
	    return undef;
	}
	return 1;
    }

    unless (defined $self->{_text}) {
	$self->warn("write called, no text");
	return undef;
    } else {
	unless (open OUT, ">$self->{_path}") {
	    $self->warn("failed to open $self->{_path} for writing: $!");
	    return undef;
	}
	print OUT $self->{_text};
	close OUT;
	return 1;
    }
}

sub diff {
    my ($self) = @_;
    my $diff;

    unless (defined $self->{_old}) {
	$self->warn("diff requested but old file contents missing");
    }
    unless (defined $self->{_text}) {
	$self->warn("diff requested but new file contents missing");
	return '';
    }
    $diff = Text::Diff::diff \$self->{_old}, \$self->{_text}, { STYLE => "Unified" };
    return $diff;
}
    
1;
