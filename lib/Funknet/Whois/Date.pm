
# Copyright (c) 2006
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

package Funknet::Whois::Date;
use strict;
use Date::Parse;
use Date::Format;

=head1 NAME 

Funknet::Whois::Date

=head1 SYNOPSIS

  my $fwd = new Funknet::Whois::Date('W3CDTF');
  my $dt = $fwd->parse_datetime('2003-02-15T13:50:05-05:00');
  
=head1 DISCUSSION

This module exists because the dependencies for
DateTime::Format::W3CDTF are *horrendous*. We implement the
parse_datetime and format_datetime methods offered by that module, by
massaging the W3CDTF style formats to and from something that
Date::Parse and Date::Format can handle.

=cut

sub new {
     my ($class, $style) = @_;
     
     # we only support W3CDTF for now.
     unless ($style eq 'W3CDTF') {
          return undef;
     }

     my $self = bless {}, $class;
     $self->{style} = $style;

     return $self;
}

sub parse_datetime {
     my ($self, $string) = @_;
     my $time = str2time($string);
     return $time;
}


sub format_datetime {
     my ($self, $time) = @_;
     return time2str('%Y-%m-%dT%H:%M:%S-00:00', $time, 0);
}

1;
