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


package Funknet::Config::CommandSet;
use strict;
use Funknet::Config::CLI;
use Funknet::Config::Root;
use Funknet::Config::RCFile;

=head1 NAME

Funknet::Config::CommandSet

=head1 DESCRIPTION

A pair of classes to hold lists of commands, and a generic
constructor. Class ::CommandSet::Host has an apply method which
executes the commands as root on the local system. Class
::CommandSet::CLI has an apply method which uses the CLI modules to
execute commands on Zebra or IOS routers. Both will return their
command lists with a text representation of where they should be
executed, for preview and warnings. 

=head1 CONSTRUCTOR

Pass in the list of commands and the target. Also pass the static
local_* values relevant. XXX -- this should come from ConfigFile.

=head1 as_text

Returns the list of commands, with a line describing where they should
be executed. For notifying proposed changes.

=head1 apply

Runs the list of commands. XXX -- needs to gain root properly, not
expect to be run as root.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = {};

    $self->{_cmds} = $args{cmds};
    if (defined $args{target} && $args{target} eq 'cli') {
	bless $self, 'Funknet::Config::CommandSet::CLI';
	return $self;
    }
    if (defined $args{target} && $args{target} eq 'host') {
	bless $self, 'Funknet::Config::CommandSet::Host';
 	return $self;
    }
    return undef;
}

sub cmds {
    my ($self) = @_;
    return @{ $self->{_cmds} };
}

package Funknet::Config::CommandSet::CLI;
use base qw/ Funknet::Config::CommandSet /;

sub as_text {
    my ($self) = @_;
    if (scalar @{ $self->{_cmds} }) {
	my $text = join "\n", @{ $self->{_cmds} };
	$text .= "\n";
	return $text;
    } else {
	return '';
    }
}

sub apply {
    my ($self) = @_;
    if (scalar @{ $self->{_cmds} }) {
	# hand off to CLI module to get these commands executed in enable mode
	my $cli = Funknet::Config::CLI->new();
	my $rv = $cli->exec_enable( $self );
	return $rv;
    } else {
	return undef;
    }
}

package Funknet::Config::CommandSet::Host;
use base qw/ Funknet::Config::CommandSet /;

sub as_text {
    my ($self) = @_;
    if (scalar @{ $self->{_cmds} }) {
	my $text = join "\n", @{ $self->{_cmds} };
	$text .= "\n";
	return $text;
    } else {
	return '';
    }
}

sub apply {
    my ($self) = @_;

# New interface to Root.pm, not quite ready yet.

#    my $root = Funknet::Config::Root->new;
#    unless ($root) {
#	die "can't get root";
#    }
#    my $rv = $root->exec_root( $self );
#    return $rv;

    if (scalar @{ $self->{_cmds} }) {
        my $text = join "\n", @{ $self->{_cmds} };
	qx[$text
];
        return $text;
    } else {
        return '';
    }
}

sub writeout {
    my ($self) = @_;

    if (scalar @{ $self->{_cmds} }) {
	my $rcfile = Funknet::Config::RCFile->new();
	$rcfile->write($self);
    }
}

1;
