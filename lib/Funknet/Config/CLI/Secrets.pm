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


package Funknet::Config::CLI::Secrets;
use strict;
use vars qw/ $username $password $enable /;

=head1 NAME

Funknet::Config::CLI::Secrets

=head1 SYNOPSIS

my $username = Funknet::Config::CLI::Secrets->username($host);
etc.

=head1 DESCRIPTION

This module is an interface to whatever sort of
authentication-material store we decide to use.

=head1 LIMITATIONS/BUGS

This module is just a placeholder for something more reasonable. We
need to hang on to usernames, passwords and enable passwords for
IOS/Zebra. 

Two issues: this is a site-local thing; we don't want a central
database of usernames and passwords. Secondly, the code will often
want to access a router on '127.0.0.1'.

=cut

sub username {
    my ($class) = @_;
    return Funknet::ConfigFile::Tools->username;
}
sub password {
    my ($class) = @_;
    return Funknet::ConfigFile::Tools->password;
}
sub enable {
    my ($class) = @_;
    return Funknet::ConfigFile::Tools->enable;
}


1;
