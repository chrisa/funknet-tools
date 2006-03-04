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

Funknet::Config::Encryption::OpenVPN

=cut

package Funknet::Config::Encryption::OpenVPN;
use strict;
use base qw/ Funknet::Config::Encryption /;

use Funknet::Debug;

=head2 init

Just some param checking and bless down into E::OpenVPN

=cut

sub init {
    my ($self, %args) = @_;
    my $l = Funknet::ConfigFile::Tools->local;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'host')) {
	$self->warn("encryption-openvpn: missing or invalid source");
	return undef;
    } else {
	$self->{_source} = $args{source};
    }
    
    unless (defined $args{certfile} && ref $args{certfile} eq 'Funknet::Config::SystemFile') {
	$self->warn("encryption-openvpn: missing or invalid certfile");
	return undef;
    } else {
	$self->{_certfile} = $args{certfile};
    }
    unless (defined $args{keyfile} && ref $args{keyfile} eq 'Funknet::Config::SystemFile') {
	$self->warn("encryption-openvpn: missing or invalid keyfile");
	return undef;
    } else {
	$self->{_keyfile} = $args{keyfile};
    }

    return $self;
}

=head2 whois_init

This method, given a 'param' value from the tunnel's encryption: attribute in the whois,
should fully populate the Encryption object by retrieving other values from the whois and 
calling the generic Encryption class constructor.

=cut

sub whois_init {
    my ($self, $tun, $param) = @_;

    # rebless into specialised Encryption class.
    bless $self, "Funknet::Config::Encryption::OpenVPN";
    
    # get key and cert SystemFile objects out of whois/keystash
    my ($keyfile, $certfile) = $self->get_keycert($param);
    
    # amend key and cert filenames to include tunnel name.
    my $tun_name  = $tun->name();
    my $path;
    $path = $keyfile->path();
    $keyfile->path("$path-$tun_name");
    $path = $certfile->path();
    $certfile->path("$path-$tun_name");

    # fire object back through init for checking 
    return $self->init(
		       source   => 'whois',
		       keyfile  => $keyfile,
		       certfile => $certfile,
		      );
}

=head2 host_init


=cut

sub host_init {
    my ($self, $tun, $param) = @_;
    
    # get the openvpn config file for this tunnel if it's there.
    my $ovpn_file = $tun->tunnel_ovpn_file();
    if (! -f $ovpn_file) {
	return undef;
    }
    
    unless (open CONF, $ovpn_file) {
        $self->warn("couldn't open $ovpn_file: $!");
	return undef;
    }
    my $ovpn_conf;
    {
	local $/ = undef;
	$ovpn_conf = <CONF>;
    }
    
    my $conf_data = _parse_openvpn_conf($ovpn_conf);
    my ($keyfile_path, $certfile_path) = ($conf_data->{key}, $conf_data->{cert});

    my $keyfile = Funknet::Config::SystemFile->new( path  => $keyfile_path,
                                                    user  => 'openvpn',
                                                    group => 'openvpn',
                                                    mode  => '0600',
                                                  );
    my $certfile = Funknet::Config::SystemFile->new( path => $certfile_path,
                                                     user  => 'openvpn',
                                                     group => 'openvpn',
                                                     mode  => '0600',
                                                   );
    
    # rebless into specialised Encryption class.
    bless $self, "Funknet::Config::Encryption::OpenVPN";
    
    # fire object back through init for checking and bless
    return $self->init(
		       source   => 'host',
		       keyfile  => $keyfile,
		       certfile => $certfile,
		      );
}

# returns the data required for the tun to be made 
# explicitly aware of its encryption.  

sub tun_data {
    my ($self) = @_;

    my $e = Funknet::ConfigFile::Tools->encryption();
    my $whois_source = Funknet::ConfigFile::Tools->whois_source || 'FUNKNET';

    if (defined $self->{_keyfile} &&
	defined $self->{_certfile}) {
	
	my $cacert_file;
	if (defined ($e->{openvpn_encr_cacert})) {
	    $cacert_file = $e->{openvpn_encr_cacert};
	} else {
	    my $encr_dir = $e->{openvpn_encr_dir};
	    $cacert_file = "$encr_dir/$whois_source-CAcert.pem";
	}
	return {
		keyfile_path  => $self->{_keyfile}->path(),
		certfile_path => $self->{_certfile}->path(),
		cafile_path   => $cacert_file,
	       };
    }
    return undef;
}

sub apply {
    my ($self) = @_;
    my $cert = $self->{_certfile};
    my $key  = $self->{_keyfile};
    return ($cert, $key);
}

sub unapply {
     my ($self) = @_;
     my $cert = $self->{_certfile}->delete();
     my $key  = $self->{_keyfile}->delete();
     return ($cert, $key);
}

sub _parse_openvpn_conf {
    my ($text) = @_;

    my $config;
    for my $line ( split /\n/, $text) {
	
	# skip blank lines; comments
	next unless $line;
	next if $line =~ /^#/;

	my ($key, $val) = $line =~ m!^(\w+)\s+(.*)$!;
	next unless ($key);
	
	$config->{$key} = $val;
    }
    
    return $config;
}

sub peer {
    my ($self) = @_;
    return $self->{_tun}->{_remote_endpoint};
}

sub get_keycert {
     my ($self, $param) = @_;

     my ($key_text, $cert_text) = $self->SUPER::get_keycert($param);
     my $e = Funknet::ConfigFile::Tools->encryption;

     $param =~ s!/!,!g;
     my $keyfile = Funknet::Config::SystemFile->new(
                                                    text  => $key_text,
                                                    user  => 'openvpn',
                                                    group => 'openvpn',
                                                    mode  => '0600',
                                                    path  => "$e->{openvpn_encr_dir}/key/$param",
                                                   );
     
     my $certfile = Funknet::Config::SystemFile->new(
                                                     text  => $cert_text,
                                                     user  => 'openvpn',
                                                     group => 'openvpn',
                                                     mode  => '0600',
                                                     path  => "$e->{openvpn_encr_dir}/cert/$param",
                                                    );
     return ($keyfile, $certfile);
}


1;
