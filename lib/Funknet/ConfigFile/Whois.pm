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

package Funknet::ConfigFile::Whois;
use strict;

use base qw/ Funknet::ConfigFile /;
our $config;

sub server_config {
    my ($self) = @_;
    if (ref $self) {
	$config = $self->{config};
    } else {
	$config = $self->get_config();
    }
    
    return { listen_address => $config->{listen_address},
	     listen_port    => $config->{listen_port},
	   };
}

sub updater_config {
    my ($self) = @_;
    if (ref $self) {
	$config = $self->{config};
    } else {
	$config = $self->get_config();
    }
    
    return { envfrom   => $config->{envfrom},
	     fromname  => $config->{fromname},
	     from      => $config->{from},
	     pubring   => $config->{pubring},
	     secring   => $config->{secring},
	     source    => $config->{whois_source},
	     objfile   => $config->{objects_file},
             timestamp => $config->{timestamp},
	   };
}

1;
