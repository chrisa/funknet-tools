# $Id$
#
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


package Funknet::Config::Interactive;
use strict;
use Funknet::Config::Validate qw/ is_ipv4 is_valid_as is_valid_router is_valid_os /;
use base qw/ Funknet::Config /;

=head1 NAME

Funknet::Config::Interactive

=head1 SYNOPSIS

  my $fci = new Funknet::Config::Interactive;
  my $config = $fci->get_config;

=head1 METHODS

=head2 new

Just a constructor. Might do slightly more at some point. 

=cut

sub new {
    my ($class,%args) = @_;
    my $self = bless {}, $class;
    
    # see if Term::Interact is available
    eval {
	require Term::Interact;
    };
    unless ($@) {
	$self->{interact_p} = 1;
    }
    return $self;
}

=head2 get_config

Call this at a point when STDOUT is a terminal, prompt the user for
config information, returns a hash suitable for use in a
F::C::ConfigFile object.

=cut

sub get_config {
    my ($self) = @_;
    my $ti = Term::Interact->new();
    
    my $config;
    
    unless (-t STDOUT && -t STDIN) {
	$self->error('interactive config requested but stdin/out are not a tty.');
	return undef;
    }

    unless ($self->{interact_p}) {
	$self->error('interactive config requested but Term::Interact not available.');
	return undef;
    }

    # STDOUT always? hmm. 
    print STDOUT "\nNo config file found. Entering interactive configuration...\n";

    $config->{local_as} = $ti->get(
				   msg        =>  'Enter your local AS number as \'ASxxxxx\'',
				   check      =>  [
						   sub{ is_valid_as(shift) },
						   '%s is not in the format ASxxxxx'
						   ],
				   );
    
    $config->{local_os} = $ti->get(
				   msg        =>  'Enter your OS (ios|bsd|linux|solaris)',
				   check      =>  [
						   sub{ is_valid_os(shift) },
						   '%s is not one of ios|bsd|linux|solaris'
						   ],
				   );
    
    $config->{local_router} = $ti->get(
				       msg        =>  'Enter your router (ios|zebra)',
				       check      =>  [
						       sub { is_valid_router(shift) },
						       '%s is not one of ios|zebra'
						       ],
				       );
    
    $config->{local_host} = $ti->get(
				     msg        =>  'Enter your host address (IPv4 dotted decimal)',
				     check      =>  [
						     sub{ is_ipv4(shift) },
						     '%s is not a valid IPv4 address'
						     ],
				     );
    
    $config->{local_endpoint} = $ti->get(
					 msg        =>  'Enter your endpoint address (IPv4 dotted decimal)',
					 check      =>  [
							 sub{ is_ipv4(shift) },
							 '%s is not a valid IPv4 address'
							 ],
					 );

    my $rtconfig_default = `which RtConfig`; chomp $rtconfig_default;
    $config->{rtconfig_path} = $ti->get(
					msg        =>  "Enter the path to RtConfig (default $rtconfig_default)",
					default    =>  $rtconfig_default,
					check      =>  [
							sub{ shift; /RtConfig$/ && -x },
							'%s is not a valid path to an RtConfig binary'
							],
					);

    $config->{password} = $ti->get(
				   msg        =>  'Enter your router password',
				  );
    
    return $config;
}

1;
