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

package Funknet::Config::CLI::Zebra::Vtysh;
use strict;
use base qw/ Funknet::Config::CLI::Zebra /;
use Funknet::Config::ConfigFile;
use IO::Socket::UNIX;

=head1 NAME

Funknet::Config::CLI::Zebra::Vtysh;

=head1 DESCRIPTION

A derivative of CLI::Zebra using Vtysh to talk to the vty. 

=cut

sub cmd {
    my ($self, $cmd) = @_;
    return undef unless defined $self->{t};
    my $fh = $self->{t};
    print $fh "$cmd\n";
    
    my ($text, $chunk);
    while(my $ret = $fh->sysread($chunk, 4096)) {
	$text .= $chunk;
	last if $chunk =~ /\0\0\0/;
    }

    return split /\n/, $text;
}

sub check_login {
    my ($self) = @_;

    return 1;
}

sub exec_enable {
    my ($self, $cmdset) = @_;

    print STDERR "in exec_enable\n";

    $self->login;
    my $fh = $self->{t};
    print $fh "enable\n";
    print $fh "$self->{_enable}\n";
    for my $cmd ($cmdset->cmds) {
        for my $cmd_line (split /\n/, $cmd) {

	    print STDERR "$cmd_line\n";

            print $fh "$cmd_line\0\0\0";
        }
    }
    print $fh "write file\n";
    print $fh "disable\n";
    $self->logout;
}


sub login {
    my ($self) = @_;
    my $l = Funknet::Config::ConfigFile->local;

    unless (defined $self->{t}) {
	my $fh = IO::Socket::UNIX->new(
				       Type => SOCK_STREAM,
				       Peer => $l->{bgpd_vty},
				      );
	die "failed to connect $l->{bgpd_vty}: $!" unless defined $fh;	  
	$self->{t} = $fh;
    } 
}

sub logout {
    my ($self) = @_;
    if (defined $self->{t}) {
	$self->{t}->close;
	$self->{t} = undef;
    }
}

1;
