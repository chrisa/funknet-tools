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

=head1 NAME

Funknet::Config::Encryption

=cut

package Funknet::Config::Encryption;
use strict;
use base qw/ Funknet::Config /;

use Funknet::Config::Validate qw/ is_valid_encryption /;
use Funknet::Config::Encryption::IPSec;
use Funknet::Config::Encryption::OpenVPN;
use Funknet::KeyStash::Client;
use Funknet::Config::SystemFile;

=head2 new

Constructor for an Encryption::* object. 

Takes the following args: 

* tun    => a F::C::Tunnel object 
* type   => the encryption to apply
* source => 'host' or 'whois', as usual.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;
    my $l = Funknet::ConfigFile::Tools->local;

    # Check basic params.

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'host')) {
	$self->warn("encryption: missing or invalid source");
	return undef;
    } else {
	$self->{_source} = $args{source};
    }
    
    unless (defined $args{tun} && (ref $args{tun}) =~ m/^Funknet::Config::Tunnel/) {
	$self->warn("encryption: missing or invalid Tunnel object");
	return undef;
    } else {
	$self->{_tun} = $args{tun};
    }

    # this is mandatory for whois source only.
    if ($self->{_source} eq 'whois') {
         unless (defined $args{type} && is_valid_encryption($args{type})) {
              $self->warn("encryption: missing or invalid type");
              return undef;
         } else {
              $self->{_type} = $args{type};
         }
    }

    # If this object is source 'whois', call the Encryption-type-specific init method.
    if ($self->{_source} eq 'whois') {
	if ($self->{_type} eq 'ipsec') {
	    Funknet::Config::Encryption::IPSec::whois_init( $self, $args{tun}, $args{param} );
	}
	if ($self->{_type} eq 'openvpn') {
	    Funknet::Config::Encryption::OpenVPN::whois_init( $self, $args{tun}, $args{param} );
	}
    }
    
    # If this object is source 'host', call the generic 'find encryption' init method.
    if ($self->{_source} eq 'host') {
       if($self->_host_init()) {
           return $self;
	} else {
           return undef;
        }
    }
    
    return $self;
}

=head2 host_init

Decide here which type of encryption to try and find.

=cut

sub _host_init {
    my ($self) = @_;
    my $tun = $self->{_tun};
    my $l = Funknet::ConfigFile::Tools->local;

    if (defined $l->{ipsec} && $tun->type ne 'tun') {

	if ($l->{ipsec} eq 'kame') {
	    bless $self, 'Funknet::Config::Encryption::IPSec::KAME';
	} elsif ($l->{ipsec} eq 'freeswan') {
	    bless $self, 'Funknet::Config::Encryption::IPSec::Freeswan';
	} else {
	    return undef;
	}
    }

    if ($tun->type eq 'tun') {
	bless $self, 'Funknet::Config::Encryption::OpenVPN';
    }

    return $self->host_init($tun);
}

sub host_init {
     # virtual
}

sub apply {
    my ($self) = @_;
    $self->warn("generic Encryption apply method called...");
    return undef;
}

sub diff {
     my ($whois, $host) = @_;
     my @changes;

     my $certdiff = $whois->{_certfile}->diff();
     my $keydiff  = $whois->{_keyfile}->diff();

     if ($certdiff) {
          push @changes, $whois->{_certfile};
     }
     if ($keydiff) {
          push @changes, $whois->{_keyfile};
     }

     return @changes;
}

# this is used by Encryption types which need a key and cert 
# (IPSec and OpenVPN)

sub get_keycert {
    my ($self, $param) = @_;

    my $k = Funknet::ConfigFile::Tools->keystash;
    my $ks = Funknet::KeyStash::Client->new(%$k);
    unless (defined $ks) {
	$self->warn("Couldn't get a KeyStash::Client");
	return undef;
    }

    # get values from whois and wherever, call $self->new( ... );
    # $param is the CN of cert in the whois.

    # get the cert. 
    my $cert = $ks->get_cert($param);
    if (!defined $cert) {
	$self->warn("certificate not found: $param");
	return undef;
    }
    my $cert_text = $cert->rawtext;

    # get the private key that corresponds to this cert
    # the CN of the cert is in the owner field
    my $cn = $cert->owner;
    if (!defined $cn) {
	$self->warn("using cert filename for key filename: $param");
	$cn = $param;
    }
    my $key_text = $ks->get_key($cn);

    if (!defined $key_text) {
	$self->warn("key not found: $cn");
	return undef;
    }

    return ($key_text, $cert_text);
}

# stub, this only applies to OpenVPN
sub tun_data {}

# virtuals for firewall rules
sub nat_firewall_rules {
     return;
}
sub filter_firewall_rules {
     return;
}

1;
