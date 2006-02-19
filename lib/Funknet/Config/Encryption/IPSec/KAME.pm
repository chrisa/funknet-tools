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

Funknet::Config::Encryption::IPSec::KAME

=cut

package Funknet::Config::Encryption::IPSec::KAME;
use strict;
use Parse::RecDescent;
use base qw/ Funknet::Config::Encryption::IPSec /;

use Data::Dumper;

=head1 METHODS

=head2 host_init

This class method takes a complete tunnel object as found from the
system, and attempts to find the KAME transport mode IPSec associated
with it. It should return a complete Funknet::Config::Encryption::-
IPSec::KAME object which will be associated with the tunnel object in
Host.pm

=cut

sub host_init {
    my ($self, $tun) = @_;
    my $e = Funknet::ConfigFile::Tools->encryption();

    # pick up params from system

    #    we do this by reading /etc/racoon/conf.d/$peer_ip_address.conf for IKE
    #    and /etc/racoon/setkey.d/$peer_ip_address.conf for policies

    my $peer = $tun->remote_endpoint;
    my $r_frag = $e->{ikepath}.'/'.$peer.'.conf';
    my $s_frag = $e->{setkeypath}.'/'.$peer.'.conf';

    # first see if the files exists. if not, shut up and return undef
    
    unless (-f $r_frag && -f $s_frag) {
	return undef;
    }

    unless (open CONF, $r_frag) {
        $self->warn("couldn't open $r_frag: $!");
	return undef;
    }
    my $racoon_conf;
    {
	local $/ = undef;
	$racoon_conf = <CONF>;
    }

    unless (open POL, $s_frag) {
        $self->warn("couldn't open $s_frag: $!");
	return undef;
    }
    my $setkey_conf;
    {
	local $/ = undef;
	$setkey_conf = <POL>;
    }

    # parse racoon.conf
    my $racoon_ret = _parse_racoon_conf($racoon_conf);
    unless ($racoon_ret) {
	$self->warn("failed to parse existing racoon.conf fragment for $peer");
    }

    # parse setkey.conf
    my $setkey_ret = _parse_setkey_conf($setkey_conf);
    unless ($setkey_ret) {
	$self->warn("failed to parse existing setkey.conf fragment for $peer");
    }
    
    # sanity check that setkey and racoon agree on the peer.
    unless ($setkey_ret->{peer} eq $racoon_ret->{peer}) {
	$self->warn("racoon and setkey disagree on peer");
	return undef;
    }

    # call the generic ipsec constructor (gets arguments validated) and return
    my $encr;

    if (!$racoon_ret) {

	# manual keying
	$encr = $self->SUPER::init( source => 'host',
				    peer   => $racoon_ret->{peer},
				    local  => $setkey_ret->{local_address},
				    proto  => $setkey_ret->{ipsec_proto},
				    policy => $setkey_ret->{ipsec_policy},
				    keying => 'manual',
				    statickeyfile => '',
				  );
    }

    if ($racoon_ret) {
	
	if ($racoon_ret->{auth_method} eq 'rsasig') {
	    
	    # we need to convert external key/cert filenames to F::C::SystemFile objects.
	    if (defined $racoon_ret->{certpath}) {
		$racoon_ret->{certpath} = Funknet::Config::SystemFile->new(
                                                                           user  => 'root',
                                                                           group => 'root',
                                                                           mode  => '0600',
                                                                           path => $racoon_ret->{certpath} 
                                                                          );
	    } else {
		$self->warn("didn't get a certpath for a configured rsasig peer");
	    }
	    if (defined $racoon_ret->{keypath}) {
		$racoon_ret->{keypath} = Funknet::Config::SystemFile->new(
                                                                          user  => 'root',
                                                                          group => 'root',
                                                                          mode  => '0600',
                                                                          path => $racoon_ret->{keypath} 
                                                                         );
	    } else {
		$self->warn("didn't get a keypath for a configured rsasig peer");
	    }

	    if ($setkey_ret->{ipsec_proto} eq 'esp') {

		# ike / certs / esp
		$encr = $self->SUPER::init( source => 'host',
					    keying => 'ike',
					    peer   => $racoon_ret->{peer},
					    local  => $setkey_ret->{local_address},
					    proto  => $setkey_ret->{ipsec_proto},
					    policy => $setkey_ret->{ipsec_policy},
					    p1encr => $racoon_ret->{encr_algs},
					    p1auth => $racoon_ret->{hash_algs},
					    dhgroup => $racoon_ret->{dhgroup},
					    p2encr => $racoon_ret->{sa_encr},
					    p2auth => $racoon_ret->{sa_auth},
					    ikemethod => 'cert',
					    certfile => $racoon_ret->{certpath},
					    privatekeyfile => $racoon_ret->{keypath},
					  );
	    }
	    
	    if ($setkey_ret->{ipsec_proto} eq 'ah') {
		
		# ike / certs / ah
		$encr = $self->SUPER::init( source => 'host',
					    keying => 'ike',
					    peer   => $racoon_ret->{peer},
					    local  => $setkey_ret->{local_address},
					    proto  => $setkey_ret->{ipsec_proto},
					    policy => $setkey_ret->{ipsec_policy},
					    p1encr => $racoon_ret->{encr_algs},
					    p1auth => $racoon_ret->{hash_algs},
					    dhgroup => $racoon_ret->{dhgroup},
					    p2auth => $racoon_ret->{sa_auth},
					    ikemethod => 'cert',
					    certfile => $racoon_ret->{certpath},
					    privatekeyfile => $racoon_ret->{keypath},
					  );
	    }
	    
	    if ($setkey_ret->{ipsec_proto} eq 'ah+esp') { # XXX

		# ike / certs / esp + ah
		$encr = $self->SUPER::init( source => 'host',
					    keying => 'ike',
					    peer   => $racoon_ret->{peer},
					    local  => $setkey_ret->{local_address},
					    proto  => $setkey_ret->{ipsec_proto},
					    policy => $setkey_ret->{ipsec_policy},
					    p1encr => $racoon_ret->{encr_algs},
					    p1auth => $racoon_ret->{hash_algs},
					    dhgroup => $racoon_ret->{dhgroup},
					    p2encr => $racoon_ret->{sa_encr},
					    p2auth => $racoon_ret->{sa_auth},
					    ikemethod => 'cert',
					    certfile => $racoon_ret->{certpath},
					    privatekeyfile => $racoon_ret->{keypath},
					  );
	    }

	}

	if ($racoon_ret->{auth_method} eq 'pre_shared_key') {
	    
	    if ($setkey_ret->{ipsec_proto} eq 'esp') {

		# ike / secret / esp
		$encr = $self->SUPER::init( source => 'host',
					    keying => 'ike',
					    peer   => $racoon_ret->{peer},
					    local  => $setkey_ret->{local_address},
					    proto  => $setkey_ret->{ipsec_proto},
					    policy => $setkey_ret->{ipsec_policy},
					    p1encr => $racoon_ret->{encr_algs},
					    p1auth => $racoon_ret->{hash_algs},
					    dhgroup => $racoon_ret->{dhgroup},
					    p2encr => $racoon_ret->{sa_encr},
					    p2auth => $racoon_ret->{sa_auth},
					    ikemethod => 'secret',
					    secretfile => $e->{pskpath},
					  );
	    }
	    
	    if ($setkey_ret->{ipsec_proto} eq 'ah') {
		
		# ike / secret / ah
		$encr = $self->SUPER::init( source => 'host',
					    keying => 'ike',
					    peer   => $racoon_ret->{peer},
					    local  => $setkey_ret->{local_address},
					    proto  => $setkey_ret->{ipsec_proto},
					    policy => $setkey_ret->{ipsec_policy},
					    p1encr => $racoon_ret->{encr_algs},
					    p1auth => $racoon_ret->{hash_algs},					       
					    dhgroup => $racoon_ret->{dhgroup},
					    p2auth => $racoon_ret->{sa_auth},
					    ikemethod => 'secret',
					    secretfile => $e->{pskpath},
					  );
	    }
	    
	    if ($setkey_ret->{ipsec_proto} eq 'ah+esp') { # XXX

		# ike / secret / esp + ah
		$encr = $self->SUPER::init( source => 'host',
					    keying => 'ike',
					    peer   => $racoon_ret->{peer},
					    local  => $setkey_ret->{local_address},
					    proto  => $setkey_ret->{ipsec_proto},
					    policy => $setkey_ret->{ipsec_policy},
					    p1encr => $racoon_ret->{encr_algs},
					    p1auth => $racoon_ret->{hash_algs},
					    dhgroup => $racoon_ret->{dhgroup},
					    p2encr => $racoon_ret->{sa_encr},
					    p2auth => $racoon_ret->{sa_auth},
					    ikemethod => 'secret',
					    secretfile => $e->{pskpath},
					  );
	    }
	}
    }
    
    return $encr;
}

sub apply {
    my ($self) = @_;
    my $e = Funknet::ConfigFile::Tools->encryption();

    # get cert/key
    my $cert = $self->{_certfile};
    my $key  = $self->{_privatekeyfile};

    my $cert_path = $cert->path;
    my $key_path  = $key->path;

    # KAME calls sha1 and md5 hmac_*, 
    # and needs commas...
    $self->{_espencr} =~ s/ /, /;
    $self->{_espauth} =~ s/ /, /;

    my $espauth = $self->{_espauth};
    $espauth =~ s/md5/hmac_md5/;
    $espauth =~ s/sha1/hmac_sha1/;


    my $racoon = <<"RACOON"; 
remote $self->{_peer}
{
        exchange_mode main;
        doi ipsec_doi;
        situation identity_only;

        certificate_type x509 "$cert_path" "$key_path";
        ca_type x509 "/etc/openvpn/ca.pem";

        my_identifier asn1dn;

        nonce_size 16;
        lifetime time 60 min;    # sec,min,hour

        proposal {
                encryption_algorithm $self->{_p1encr};
                hash_algorithm $self->{_p1auth};
                authentication_method rsasig;
                dh_group $self->{_dhgroup};
        }
}

sainfo address $self->{_local} 4 address $self->{_peer} 4
{
        pfs_group $self->{_dhgroup};
        lifetime time 60 min;
        encryption_algorithm $self->{_espencr};
        authentication_algorithm $espauth;
        compression_algorithm deflate;
}

RACOON

    my $setkey;

    if ($self->{_policy} eq 'ipip-trans') {
	
	if ($self->{_proto} eq 'esp') {
	
	    $setkey = <<"SETKEY";

spdadd $self->{_local} $self->{_peer} 4 -P out ipsec
esp/transport/$self->{_local}-$self->{_peer}/require;
spdadd $self->{_peer} $self->{_local} 4 -P in ipsec
esp/transport/$self->{_peer}-$self->{_local}/require;

SETKEY
	} elsif ($self->{_proto} eq 'ah') {
	    
	    $setkey = <<"SETKEY";

spdadd $self->{_local} $self->{_peer} 4 -P out ipsec
ah/transport/$self->{_local}-$self->{_peer}/require;
spdadd $self->{_peer} $self->{_local} 4 -P in ipsec
ah/transport/$self->{_peer}-$self->{_local}/require;

SETKEY

	} elsif ($self->{_proto} eq 'ah+esp') {
	    
	    $setkey = <<"SETKEY";

spdadd $self->{_local} $self->{_peer} 4 -P out ipsec
esp/transport/$self->{_local}-$self->{_peer}/require ah/transport/$self->{_local}-$self->{_peer}/require;
spdadd $self->{_peer} $self->{_local} 4 -P in ipsec
esp/transport/$self->{_peer}-$self->{_local}/require ah/transport/$self->{_peer}-$self->{_local}/require;

SETKEY
	    
	} else {
	    $self->warn("unknown ipsec protocol in setkey: $self->{_proto}");
	    return undef;
	}
    } 

    # create a racoon.conf fragment
    my $racoon_conf = Funknet::Config::SystemFile->new( 
                                                       user  => 'root',
                                                       group => 'root',
                                                       mode  => '0600',
                                                       text => "# $self->{_peer} racoon.conf fragment\n".$racoon,
                                                       path => $e->{ikepath}.'/'.$self->{_peer}.".conf" 
                                                      );
    

    # create a setkey.conf fragment
    my $setkey_conf = Funknet::Config::SystemFile->new(
                                                       user  => 'root',
                                                       group => 'root',
                                                       mode  => '0600',
                                                       text => "# $self->{_peer} setkey.conf fragment\n".$setkey,
                                                       path => $e->{setkeypath}.'/'.$self->{_peer}.".conf" 
                                                      );

    return (
	    $racoon_conf, $setkey_conf,
	    $cert, $key
	   );
}


sub _parse_racoon_conf {
    my ($conf) = @_;
    my $grammar = q{

start: remote_section sainfo_section

peer_addr: ip_addr
 { $RES::peer = $item[1]; }

ip_addr: /(\d+)\.(\d+)\.(\d+)\.(\d+)/
prefix: ip_addr '/' /(\d+)/

remote_section: 'remote' peer_addr '{' remote_keyval(s) proposal_section '}'
remote_keyval:  remote_key ';'
remote_key: 'exchange_mode' exchange_mode
                 { $RES::mode = $item[2]; }

          | 'doi' doi
                 { $RES::doi = $item[2]; }

          | 'situation' situation
                 { $RES::situation = $item[2]; }

          | 'generate_policy' generate_policy
                 { $RES::generate  = $item[2]; }

          | 'proposal_check' proposal_check
                 { $RES::prop_check  = $item[2]; }

          | 'nonce_size' nonce_size
                 { $RES::nonce = $item[2]; }

          | 'lifetime time' lifetime timeunit
                 { $RES::lifetime = "$item[2] $item[3]"; }

          | 'my_identifier' identifier[ 'my' ]
          | 'peers_identifier' identifier[ 'peers' ]
          | 'certificate_type' certificate_type

proposal_section: 'proposal {' proposal_keyval(s) '}'
proposal_keyval: proposal_key ';'
proposal_key: 'encryption_algorithm' encr_alg(s)
                 { $RES::encr_algs = $item[2]; }

            | 'hash_algorithm' hash_alg(s)
                 { $RES::hash_algs = $item[2]; }

            | 'authentication_method' authentication_method
                 { $RES::auth_method = $item[2]; }

            | 'dh_group' dh_group
                 { $RES::dhgroup = $item[2]; }

exchange_mode: 'main,aggressive' 
             | 'aggressive,main'
             | 'main' 
             | 'aggressive' 


doi:               'ipsec_doi'
situation:         'identity_only'
generate_policy:   'on' | 'off'
proposal_check:    'obey' | 'strict' | 'claim' | 'exact'
nonce_size:        /\d+/
lifetime:          /\d+/
timeunit:          'sec' | 'min' | 'hour'

certificate_type:  'x509' path[ 'cert' ] path[ 'key' ]
 { $RES::cert_type = $item[1]; }

authentication_method: 'pre_shared_key' | 'rsasig'
dh_group: '1' | '2' | '5' | 'modp768' | 'modp1024' | 'modp1536'
encr_alg: 'aes' | '3des' | 'des'
hash_alg: 'sha' | 'md5' | 'hmac_sha1' | 'hmac_md5'
comp_alg: 'deflate'

path: /"?(\/[^\/"]+)+"?/
 { 
   if ($arg[0] eq 'cert') { $RES::certpath = $item[1]; }
   if ($arg[0] eq 'key')  { $RES::keypath  = $item[1]; }
 }

identifier: address | fqdn | user_fqdn | keyid | asn1dn

address:   'address'   ip_addr
 {
   if ($arg[0] eq 'my')    { $RES::my_id =    "$item[1] $item[2]"; }
   if ($arg[0] eq 'peers') { $RES::peers_id = "$item[1] $item[2]"; }
 }
fqdn:      'fqdn'      /"?[a-z.]+"?/
 {
   if ($arg[0] eq 'my')    { $RES::my_id =    "$item[1] $item[2]"; }
   if ($arg[0] eq 'peers') { $RES::peers_id = "$item[1] $item[2]"; }
 }
user_fqdn: 'user_fqdn' /[^;]+/ 
 {
   if ($arg[0] eq 'my')    { $RES::my_id =    "$item[1] $item[2]"; }
   if ($arg[0] eq 'peers') { $RES::peers_id = "$item[1] $item[2]"; }
 }
keyid:     'keyid'     /\d+/
 {
   if ($arg[0] eq 'my')    { $RES::my_id =    "$item[1] $item[2]"; }
   if ($arg[0] eq 'peers') { $RES::peers_id = "$item[1] $item[2]"; }
 }
asn1dn:    'asn1dn'    /[^;]+/
 {
   if ($arg[0] eq 'my')    { $RES::my_id    = "$item[1] $item[2]"; }
   if ($arg[0] eq 'peers') { $RES::peers_id = "$item[1] $item[2]"; }
 }

sainfo_section: 'sainfo' sainfo_id '{' sainfo_keyval(s) '}'
sainfo_id: 'anonymous' | sainfo_specific
sainfo_specific: 'address' sa_local_prefix 'address' sa_remote_prefix
sa_local_prefix: sa_ip_addr sa_port(?) sa_proto(?)
       { $RES::sa_local = "$item[1]"; }
sa_remote_prefix: sa_ip_addr sa_port(?) sa_proto(?)
       {$RES::sa_remote = "$item[1]"; }
sa_ip_addr: ip_addr | ip_addr '/' /(\d+)/
sa_proto: /(\d+)/ | 'any' | 'ipip'
sa_port: /\[(\d+)\]/ | '[any]'
sainfo_keyval:  sainfo_key ';'
sainfo_key: 'lifetime time' lifetime timeunit
                 { $RES::sa_lifetime = "$item[2] $item[3]"; }

          | 'encryption_algorithm' encr_alg(s)
                 { $RES::sa_encr = $item[2]; }

          | 'authentication_algorithm' hash_alg(s)
                 { $RES::sa_auth = $item[2]; }

          | 'compression_algorithm' comp_alg(s)
                 { $RES::sa_comp = $item[2]; }

          | 'pfs_group' dh_group
                 { $RES::sa_pfs = $item[2]; }

};

    my $parser = new Parse::RecDescent ($grammar) or die "Bad grammar!\n";

    # strip comments
    my $text;
    for my $line (split /\n/, $conf) {
	chomp $line;
	$line =~ s/#.*$//;
	$text .= "$line\n";
    }
    
    defined $parser->start($text) or print "Bad text!\n";

    my $data = {
		sa_local    => $RES::sa_local,
		sa_remote   => $RES::sa_remote,
		sa_lifetime => $RES::sa_lifetime,
		sa_encr     => $RES::sa_encr,
		sa_auth     => $RES::sa_auth,
		sa_comp     => $RES::sa_comp,
		auth_method => $RES::auth_method,
		hash_algs   => $RES::hash_algs,
		encr_algs   => $RES::encr_algs,
		my_id       => $RES::my_id,
		peers_id    => $RES::peers_id,
		peer        => $RES::peer,
		mode        => $RES::mode,
		doi         => $RES::doi,
		situation   => $RES::situation,
		generate    => $RES::generate,
		prop_check  => $RES::prop_check,
		cert_type   => $RES::cert_type,
		certpath    => $RES::certpath,
		keypath     => $RES::keypath,
		nonce       => $RES::nonce,
		lifetime    => $RES::lifetime,
		dhgroup     => $RES::dhgroup,
	       };

    # pathnames may have double quotes around them -- remove these, as the parser doesn't.

    for my $attr (qw/ certpath keypath /) {
	$data->{$attr} =~ s/"//g;
    }
    
    # algorithm lists need to be converted from arrayrefs to space-separated strings.
    # but - if there was only one alg, it won't just be in a one-element list. so:
    
    for my $attr (qw/ sa_encr sa_auth hash_algs encr_algs /) {
	if (ref $data->{$attr}) {
	    $data->{$attr} = join ' ', @{ $data->{$attr} };
	}
    }

    # KAME is odd - change these back.
    $data->{sa_auth} =~ s/hmac_md5/md5/;
    $data->{sa_auth} =~ s/hmac_sha1/sha/;

    return $data;
}

sub _parse_setkey_conf {
    my ($conf) = @_;

    # strip comments
    my $text;
    for my $line (split /\n/, $conf) {
        chomp $line;
        $line =~ s/#.*$//;
	if ($line) {
	    $text .= "$line\n";
	}
    }

    # chop up, tidy
    my @stanzas = split ";", $text;
    for my $s (@stanzas) {
	$s =~ s/\n/ /gs;
	$s =~ s/^ //g;
	$s =~ s/ $//g;
    }

    my $data;    
    for my $s (@stanzas) {
	next if $s =~ /^\s*$/;

	if ($s =~ m!spdadd\s+(\d+\.\d+\.\d+\.\d+)\s*(\[\d+\])?\s+(\d+\.\d+\.\d+\.\d+)\s*(\[\d+\])?\s+(any|\d+|ipip|gre)\s+-P\s+(in|out)\s+ipsec\s+(esp|ah)/(tunnel|transport)/(.*)/(permit|apply|require)!) {

	    my $dir = $6;

	    if ($dir eq 'in') {
		
		$data->{in}->{peer} = $1;
		$data->{in}->{dir} = $dir;
		$data->{in}->{proto} = $5;
		$data->{in}->{local_port} = $4;
		$data->{in}->{remote_port} = $2;
		$data->{in}->{local_addr} = $3;
		$data->{in}->{ipsec_proto} = $7;
		$data->{in}->{ipsec_mode} = $8;
		$data->{in}->{ipsec_policy} = $10;

	    } elsif ($dir eq 'out') {

		$data->{out}->{peer} = $3;
		$data->{out}->{dir} = $dir;
		$data->{out}->{proto} = $5;
		$data->{out}->{local_port} = $2;
		$data->{out}->{remote_port} = $4;
		$data->{out}->{local_addr} = $1;
		$data->{out}->{ipsec_proto} = $7;
		$data->{out}->{ipsec_mode} = $8;
		$data->{out}->{ipsec_policy} = $10;

	    } else {
		warn "dir not in or out...";
	    }
	} else {
	    warn "failed to match setkey stanza";
	}
    }
    
    # check here that things are in agreement .. XXX
    $data->{local_address} = $data->{in}->{local_addr};
    $data->{ipsec_proto} = $data->{in}->{ipsec_proto};
    $data->{peer} = $data->{in}->{peer};
    
    # tidy ports
    $data->{in}->{local_port} =~ s/\[(\d+)\]/$1/;
    $data->{in}->{remote_port} =~ s/\[(\d+)\]/$1/;

    $data->{out}->{local_port} =~ s/\[(\d+)\]/$1/;
    $data->{out}->{remote_port} =~ s/\[(\d+)\]/$1/;

    # work out what 'policy' this is -- see F::C::Validate::is_valid_policy
    # (i.e. ipip-trans for ipip tunnels with transport mode encryption.)

    if ($data->{in}->{proto} eq 'ipip' &&
	$data->{out}->{proto} eq 'ipip' &&
	$data->{in}->{ipsec_mode} eq 'transport' &&
	$data->{out}->{ipsec_mode} eq 'transport') {
	    
	$data->{ipsec_policy} = 'ipip-trans';
    } else {
	$data->{ipsec_policy} = 'unknown';
    }

    return $data;
}

1;
