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

package Funknet::ConfigFile::Tools;
use strict;

use base qw/ Funknet::ConfigFile /;
use Funknet::Debug;
use Funknet::Config::Validate qw/ 	is_valid_as is_valid_os is_valid_router
					is_ipv4 is_valid_firewall
					is_valid_ipfw_rule_num
				/;
our $config;

sub local {
    my ($self) = @_;
    if (ref $self) {
	$config = $self->{config};
    } else {
	$config = $self->get_config();
    }
    
    return { as              => $config->{local_as},
	     os              => $config->{local_os},
	     host            => $config->{local_host},
	     router          => $config->{local_router},
	     endpoint        => $config->{local_endpoint},
	     source          => $config->{local_source},
             public_endpoint => $config->{local_public_endpoint},
	     ipsec           => $config->{local_ipsec},
	     bgpd_vty        => $config->{local_bgpd_vty},
	     firewall_type   => $config->{firewall_type},
	     min_ipfw_rule   => $config->{min_ipfw_rule},
	     max_ipfw_rule   => $config->{max_ipfw_rule},
	   };
}

sub encryption {
    my ($self) = @_;
    if (ref $self) {
	$config = $self->{config};
    } else {
	$config = $self->get_config();
    }
    
    _validate_encryption_config($config);
    
    return { ipsec			=> $config->{encr_ipsec},
	     cipher1			=> $config->{encr_cipher1},
	     hash1			=> $config->{encr_hash1},
	     cipher2			=> $config->{encr_cipher2},
	     hash2			=> $config->{encr_hash2},
	     proto			=> $config->{encr_proto},
	     dhgroup			=> $config->{encr_dhgroup},
	     openvpn_encr_dir		=> $config->{encr_dir_openvpn},
	     openvpn_encr_cacert	=> $config->{encr_cacert_openvpn},
	     openvpn_conf_dir		=> $config->{openvpn_conf_dir},
	     ipsec_encr_dir		=> $config->{encr_dir_ipsec},
	     ipsec_encr_cacert		=> $config->{encr_cacert_ipsec},
	     ikepath			=> $config->{encr_ikepath},
	     setkeypath			=> $config->{encr_setkeypath},
	     pskpath			=> $config->{encr_pskpath},
	   };
}

sub keystash {
    my ($self) = @_;
    if (ref $self) {
	$config = $self->{config};
    } else {
	$config = $self->get_config();
    }
    
    return { www_user => $config->{ks_www_user},
	     www_pass => $config->{ks_www_pass},
	     www_host => $config->{ks_www_host},
	     www_cert => $config->{ks_www_cert},
	     www_ca   => $config->{ks_www_ca},

	     path => $config->{ks_path},

	     whois_host   => $config->{ks_whois_host},
	     whois_port   => $config->{ks_whois_port},
	     whois_source => $config->{ks_whois_source},
	   };
}
    
sub validate_local_config {
    my ($self) = @_;
    if (ref $self) {
	$config = $self->{config};
    } else {
	$config = $self->get_config();
    }

    unless (is_valid_as($config->{local_as})) {
	$self->_exit_with_error("Invalid local_as $config->{local_as}");
    }

    foreach my $os (_local_os_types($config)) {
	unless (is_valid_os($os)) {
	    $self->_exit_with_error("Invalid local_os $os");
	}
    }

    unless (is_ipv4($config->{local_host})) {
	$self->_exit_with_error("Invalid local_host $config->{local_host}");
    }

    unless (is_valid_router($config->{local_router})) {
	$self->_exit_with_error("Invalid local_router $config->{local_router}");
    }

    unless (is_ipv4($config->{local_endpoint})) {
	$self->_exit_with_error("Invalid local_endpoint $config->{local_endpoint}");
    }

    if (defined ($config->{local_public_endpoint})) {
	unless (is_ipv4($config->{local_public_endpoint})) {
	    $self->_exit_with_error("Invalid local_public_endpoint $config->{local_public_endpoint}");
	}
    }

    if (defined ($config->{firewall_type})) {
	unless (is_valid_firewall($config->{firewall_type})) {
	    $self->_exit_with_error("Invalid firewall_type $config->{firewall_type}");
	}

	if ($config->{firewall_type} eq 'ipfw') {
	    unless (is_valid_ipfw_rule_num($config->{min_ipfw_rule})) {
	    	$self->_exit_with_error("Invalid min_ipfw_rule");
	    }
	    unless (is_valid_ipfw_rule_num($config->{max_ipfw_rule})) {
	    	$self->_exit_with_error("Invalid max_ipfw_rule");
	    }
	    unless ($config->{max_ipfw_rule} > $config->{min_ipfw_rule}) {
		$self->_exit_with_error("min_ipfw_rule is greater than max_ipfw_rule");
	    }
	}
    }
}

sub _validate_encryption_config {
    my ($config) = @_;

    unless (defined ($config->{ks_path})) {
	die("encryption enabled, but ks_path not set");
    }
    
    if (grep /openvpn/, _local_os_types($config)) {

        unless (defined ($config->{openvpn_conf_dir})) {
	    die("OpenVPN selected, but openvpn_conf_dir not set");
	}

        unless (defined ($config->{encr_dir_openvpn})) {
	    die("OpenVPN selected, but encr_dir_openvpn not set");
	}

	if ($config->{ks_path} eq $config->{encr_dir_openvpn}) {
            die("encr_dir_openvpn and ks_path cannot be the same");
	}
    }

    if (defined ($config->{local_ipsec})) {

	unless (defined ($config->{encr_dir_ipsec})) {
            die("local_ipsec is set, but encr_dir_ipsec is not");
	}

	if ($config->{ks_path} eq $config->{encr_dir_ipsec}) {
            die("encr_dir_ipsec and ks_path cannot be the same");
	}
    }
}

sub _local_os_types {
    my ($config) = @_;

    my @types;

    if ((ref($config->{local_os} )) eq 'ARRAY') {
        foreach my $os (@{$config->{local_os}}) {
		push (@types, $os);
	}
    } else {
	push (@types, $config->{local_os});
    }

    return(@types);
}

sub _exit_with_error {
    my ($self, $msg) = @_;

    print STDERR "$msg in $self->{file}\n";
    exit(1);
}

1;
