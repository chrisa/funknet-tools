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


package Funknet::Config::Root;
use strict;

=head1 NAME

Funknet::Config::Root

=head1 DESCRIPTION

Class abstracting methods of getting root. 

=head1 METHODS

=head2 new

=head2 exec_root

=head2 pipe_root

=cut


use Data::Dumper;

sub new {
    my ($class) = @_;
    my $self = bless {}, $class;

    my $root_method = Funknet::Config::ConfigFile->root;

    if ($root_method eq 'sudo') {
	
	$self->{_exec} = sub ($) {
	    my ($cmd) = @_;
	    system "sudo $cmd";
	};
	
	$self->{_pipe} = sub ($) {
	    my ($cmd, $data) = @_;
	    open PIPE, "|sudo $cmd" 
		or Funknet::Config::error("couldn't pipe to sudo $cmd");
	    print PIPE $data;
	};
	return $self;
		      
    } elsif ($root_method eq 'userv') {
		    
      $self->{_exec} = 
	sub ($) {
	  my ($cmd) = @_;
	  system "userv $cmd"; # XXX this isn't right
	};
      
      $self->{_pipe} = sub ($) {
	  my ($cmd, $data) = @_;
	  open PIPE, "|userv $cmd" # XXX neither's this, most likely.
	    or Funknet::Config::error("couldn't pipe to userv $cmd");
	  print PIPE $data;
	};
	return $self;

    } elsif ($root_method eq 'runas') {

	$self->{_exec} =
	  sub ($) {
	    my ($cmd) = @_;
	    system "$cmd";
	  };

	$self->{_pipe} = sub ($) {
	  my ($cmd, $data) = @_;
	  open PIPE, "|$cmd" 
	    or Funknet::Config::error("couldn't pipe to $cmd");
	  print PIPE $data;
	};
	return $self;

    } else {
	return undef;
    }
}

sub exec_root {
    my ($self, $cmdset) = @_;

    for my $cmd ($cmdset->cmds) {
	&{ $self->{_exec} }($cmd);
    }
}

sub pipe_root {
    my ($self, $cmd, $data) = @_;

    &{ $self->{_pipe} }($cmd, $data);
}

1;
