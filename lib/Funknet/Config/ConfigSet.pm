#!/usr/bin/perl -w
#
# $Id$
#
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


package Funknet::Config::ConfigSet;
use strict;

=head1 NAME

Funknet::Config::ConfigSet

=head1 DESCRIPTION

A container class for SystemFiles and CommandSets

=head1 METHODS

=head2 new

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    if (defined $args{files}) {
	$self->{_files} = $args{files};
    }
    if (defined $args{cmds}) {
	$self->{_cmds} = $args{cmds};
    }

    return $self;
}

sub as_text {
    my ($self) = @_;
    
    my $text = "";

    if (defined $self->{_files}) {
	for my $file (@{ $self->{_files} }) {
	    $text .= $file->as_text;
	}
    }

    if (defined $self->{_cmds}) {
	for my $cmd (@{ $self->{_cmds} }) {
	    $text .= $cmd->as_text;
	}
    }
    
    return $text;
}

sub apply {
    my ($self) = @_;
    
    if (defined $self->{_files}) {
	for my $file (@{ $self->{_files} }) {
	    $file->apply;
	}
    }

    if (defined $self->{_cmds}) {
	for my $cmd (@{ $self->{_cmds} }) {
	    $cmd->apply;
	}
    }
}

1;
