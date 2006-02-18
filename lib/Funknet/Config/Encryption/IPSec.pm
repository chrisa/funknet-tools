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

Funknet::Config::Encryption::IPSec

=cut

package Funknet::Config::Encryption::IPSec;
use strict;
use base qw/ Funknet::Config::Encryption /;

use Funknet::Config::Encryption::IPSec::KAME;
use Funknet::Config::Encryption::IPSec::Freeswan;
use Funknet::Config::Validate qw/ :ipsec is_ipv4 is_valid_filepath /;

=head2 whois_init

This method, given a 'param' value from the tunnel's encryption: attribute in the whois,
should fully populate the Encryption object by retrieving other values from the whois and 
calling the generic Encryption class constructor.

=cut

sub whois_init {
    my ($self, $tun, $param) = @_;
    my $e = Funknet::ConfigFile::Tools->encryption;
    
    # policy
    my $policy;
    my $tun_type = $tun->type;
    if ($tun_type eq 'ipip') {
	$policy = 'ipip-trans';
    } 
    # more policy defs ...

    unless (defined $policy) {
	$self->warn("couldn't establish ipsec policy for tunnel type $tun_type");
	return undef;
    }

    # rebless into specific class for type of ipsec 

    if ($e->{ipsec} eq 'kame') {
	bless $self, 'Funknet::Config::Encryption::IPSec::KAME';
    } elsif ($e->{ipsec} eq 'freeswan') {
	bless $self, 'Funknet::Config::Encryption::IPSec::Freeswan';
    } else {
	return undef;
    }

    # get key and cert SystemFile objects.
    my ($keyfile, $certfile) = $self->get_keycert($param);
    
    $self->init(
		policy         => $policy,
		peer           => $tun->remote_endpoint,
		local          => $tun->local_endpoint,
		source         => 'whois',
		keying         => 'ike', # implied by certs
		ikemethod      => 'cert', # also implied
		proto          => $e->{proto},
		p1encr         => $e->{cipher1},
		p1auth         => $e->{hash1},
	        dhgroup        => $e->{dhgroup},
		p2encr         => $e->{cipher2},
		p2auth         => $e->{hash2},
		certfile       => $certfile,
		privatekeyfile => $keyfile,
	       );

    return $self;
}


=head2 new


=cut

sub init {
    my ($self, %args) = @_;
    my $l = Funknet::ConfigFile::Tools->local;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'host')) {
	$self->warn("encryption-ipsec: missing or invalid source");
	return undef;
    } else {
	$self->{_source} = $args{source};
    }

    unless (defined $args{peer} && is_ipv4($args{peer})) {
	$self->warn("encryption-ipsec: missing or invalid peer");
	return undef;
    } else {
	$self->{_peer} = $args{peer};
    }

    unless (defined $args{local} && is_ipv4($args{local})) {
	$self->warn("encryption-ipsec: $self->{_peer}: missing or invalid local address");
	return undef;
    } else {
	$self->{_local} = $args{local};
    }
    
    # we expect to get the following:

    # keying:          ike / manual       'keying'
    # ipsec protocols: esp / ah / esp+ah  'proto'
    # ipsec policy:    ipip-trans / etc   'policy'

    # p1 encr cipher:  a cipher           'p1encr' 
    # p1 auth cipher:  a cipher           'p1auth'
    # p1 dh group:     1 / 2 / 5 / nopfs  'dhgroup'
    # ike auth:        secret / cert      'ikemethod'
    # cert file:       path               'certfile'
    # privatekey file: path               'privatekeyfile'
    # secret file:     path               'secretfile'

    # esp cipher auth: a cipher           'espauth'
    # esp cipher encr: a cipher           'espencr'
    # ah cipher:       a cipher           'ahauth'
    # statickey file:  path               'statickeyfile'

    unless (defined $args{proto} && is_valid_ipsec_proto($args{proto})) {
	$self->warn("encryption-ipsec: $self->{_peer}: missing or invalid proto");
	return undef;
    } else {
	$self->{_proto} = $args{proto};
    }

    unless (defined $args{policy} && is_valid_ipsec_policy($args{policy})) {
	$self->warn("encryption-ipsec: $self->{_peer}: missing or invalid policy");
	return undef;
    } else {
	$self->{_policy} = $args{policy};
    }

    unless (defined $args{keying} && is_valid_ipsec_keying($args{keying})) {
	$self->warn("encryption-ipsec: $self->{_peer}: missing or invalid keying");
	return undef;
    } else {
	$self->{_keying} = $args{keying};
    }
    
    # auto keying things: p1 encr, p1 auth, p1 dhgroup, ikemethod
    if ($self->{_keying} eq 'ike') {

	unless (defined $args{p1encr} && is_valid_ipsec_cipher($args{p1encr})) {
	    $self->warn("encryption-ipsec: $self->{_peer}: missing or invalid p1encr");
	    return undef;
	} else {
	    $self->{_p1encr} = $args{p1encr};
	}

	unless (defined $args{p1auth} && is_valid_ipsec_hash($args{p1auth})) {
	    $self->warn("encryption-ipsec: $self->{_peer}: missing or invalid p1auth");
	    return undef;
	} else {
	    $self->{_p1auth} = $args{p1auth};
	}

	unless (defined $args{dhgroup} && is_valid_ipsec_dhgroup($args{dhgroup})) {
	    $self->warn("encryption-ipsec: $self->{_peer}: missing or invalid dhgroup");
	    return undef;
	} else {
	    $self->{_dhgroup} = $args{dhgroup};
	}

	unless (defined $args{ikemethod} && is_valid_ipsec_ikemethod($args{ikemethod})) {
	    $self->warn("encryption-ipsec: $self->{_peer}: missing or invalid ikemethod");
	    return undef;
	} else {
	    $self->{_ikemethod} = $args{ikemethod};
	}

	if ($self->{_ikemethod} eq 'secret') {
	
	    unless (defined $args{secretfile} && is_valid_filepath($args{secretfile})) {
		$self->warn("encryption-ipsec: $self->{_peer}: missing or invalid secretfile");
		return undef;
	    } else {
		$self->{_secretfile} = $args{secretfile};
	    }

	} elsif ($self->{_ikemethod} eq 'cert') {

	    unless (defined $args{certfile} && is_valid_filepath($args{certfile})) {
		$self->warn("encryption-ipsec: $self->{_peer}: missing or invalid certfile");
		return undef;
	    } else {
		$self->{_certfile} = $args{certfile};
	    }

	    unless (defined $args{privatekeyfile} && is_valid_filepath($args{privatekeyfile})) {
		$self->warn("encryption-ipsec: $self->{_peer}: missing or invalid privatekeyfile");
		return undef;
	    } else {
		$self->{_privatekeyfile} = $args{privatekeyfile};
	    }
	}
	
    } elsif ($self->{_keying} eq 'manual') {
	
	unless (defined $args{statickeyfile} && is_valid_filepath($args{statickeyfile})) {
	    $self->warn("encryption-ipsec: $self->{_peer}: missing or invalid statickeyfile");
	    return undef;
	} else {
	    $self->{_statickeyfile} = $args{statickeyfile};
	}

    } else {
	# nothing, shouldn't happen
    }
    
    if ($self->{_proto} =~ /esp/) {

	unless (defined $args{p2auth} && is_valid_ipsec_hash($args{p2auth})) {
	    $self->warn("encryption-ipsec: $self->{_peer}: missing or invalid p2auth");
	    return undef;
	} else {
	    $self->{_espauth} = $args{p2auth};
	}
	
	unless (defined $args{p2encr} && is_valid_ipsec_cipher($args{p2encr})) {
	    $self->warn("encryption-ipsec: $self->{_peer}: missing or invalid p2encr");
	    return undef;
	} else {
	    $self->{_espencr} = $args{p2encr};
	}

    } 

    if ($self->{_proto} =~ /ah/) {
	unless (defined $args{p2auth} && is_valid_ipsec_hash($args{p2auth})) {
	    $self->warn("encryption-ipsec: $self->{_peer}: missing or invalid p2auth");
	    return undef;
	} else {
	    $self->{_ahauth} = $args{p2auth};
	}
    }

    return $self;
}

sub peer {
    my ($self) = @_;
    return $self->{_peer};
}

sub get_keycert {
     my ($self, $param) = @_;

     my ($key_text, $cert_text) = $self->SUPER::get_keycert($param);
     my $e = Funknet::ConfigFile::Tools->encryption;

     my $keyfile = Funknet::Config::SystemFile->new(
                                                    text  => $key_text,
                                                    user  => 'root',
                                                    group => 'root',
                                                    mode  => '0600',
                                                    path  => "$e->{keypath}/$param",
                                                   );
     
     my $certfile = Funknet::Config::SystemFile->new(
                                                     text  => $cert_text,
                                                     user  => 'root',
                                                     group => 'root',
                                                     mode  => '0600',
                                                     path  => "$e->{certpath}/$param",
                                                    );
     return ($keyfile, $certfile);
}

1;
