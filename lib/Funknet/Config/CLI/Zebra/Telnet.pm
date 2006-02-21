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

package Funknet::Config::CLI::Zebra::Telnet;
use strict;

use base qw/ Funknet::Config::CLI::Zebra /;

use Funknet::ConfigFile::Tools;
use Funknet::Debug;

=head1 NAME

Funknet::Config::CLI::Zebra::Telnet;

=head1 DESCRIPTION

A derivative of CLI::Zebra using Telnet to talk to the vty. 

=cut

sub cmd {
    my ($self, $cmd) = @_;
    return undef unless defined $self->{t};
    debug("running: $cmd");
    $self->{t}->print($cmd);
    my @output;
    while( my $line = $self->{t}->getline( Timeout => 1) ) {
        last if $line =~ />$/;
        push @output, $line;
    }
    return @output;
}

sub check_login {
    my ($self) = @_;

    return 1;

    $self->login;
    $self->{t}->cmd('enable');
    $self->{t}->cmd($self->{_enable});
    my $p = $self->{t}->getline;
    $self->logout;
    if ($p =~ /#/) {
	return 1;
    } else {
	return undef;
    }
}

sub exec_enable {
    my ($self, $cmdset) = @_;

    $self->login;
    $self->{t}->input_log(\*STDOUT);
    $self->{t}->cmd('enable');
    $self->{t}->cmd($self->{_enable});
    for my $cmd ($cmdset->cmds) {
        for my $cmd_line (split /\n/, $cmd) {
            $self->{t}->cmd($cmd_line);
            select(undef,undef,undef,0.2);
        }
    }
    $self->{t}->cmd('write file');
    $self->{t}->cmd('disable');
    $self->logout;
}


sub login {
    my ($self) = @_;
    my $l = Funknet::ConfigFile::Tools->local;

    require Net::Telnet;
    unless (defined $self->{t}) {
	$self->{t} = Net::Telnet->new( Timeout => 10,
				       Prompt  => '/[ \>\#]$/',
				       Port    => 2605,
                                       Errmode => 'return',
				     );
	
	$self->{t}->open($l->{host});
	$self->{t}->cmd($self->{_password});
	$self->{t}->cmd('terminal length 0');
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
