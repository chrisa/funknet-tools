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

package Funknet::Tools::ObjectGenerator;
use strict;
use Funknet::Whois qw/ get_object get_object_inverse /;
use Funknet::Whois::ObjectGenerator;
use Funknet::Config::Validate qw/ is_ipv4 /;

use Data::Dumper;

# error buffer.
our @errors;

=head1 DESCRIPTION

Reasonable interface to the Funknet::Whois::ObjectGenerator stuff.

=cut

sub person {
    my (%args) = @_;

    unless (defined $args{name}) {
	error( "didn't get a name" );
    }
    unless (defined $args{address}) {
	error( "didn't get an address" );
    }
    unless (defined $args{e_mail}) {
	error( "didn't get an email address" );
    }
    unless (defined $args{phone}) {
	error( "didn't get a phone number" );
    }

    if (scalar @errors > 0) {
	return undef;
    }
    
    my $gen = Funknet::Whois::ObjectGenerator->new( source => 'FUNKNET' );
    my $me = $gen->person( 'name'    => $args{name},
			   'address' => $args{address},
			   'e_mail'  => $args{e_mail},
			   'phone'   => $args{phone},
			 );
    unless (defined $me) {
	error("creating person object: \n".$gen->error);
	return undef;
    } else {
	return $me;
    }
}

sub key_cert {
    my (%args) = @_;

    unless (defined $args{name}) {
	error( "didn't get a name" );
    }
    unless (defined $args{changed}) {
	error( "didn't get an email address for 'changed:'" );
    }
    unless (defined $args{certif}) {
	error( "didn't get the key material" );
    }

    if (scalar @errors > 0) {
	return undef;
    }
    
    my $gen = Funknet::Whois::ObjectGenerator->new( source => 'FUNKNET' );
    my $key = $gen->key_cert( 'name'    => $args{name},
			      'e_mail'  => $args{changed},
			      'certif'  => $args{certif},
			    );
    unless (defined $key) {
	error("creating key-cert: \n".$gen->error);
	return undef;
    } else {
	return $key;
    }
}

sub mntner {
    my (%args) = @_;

    unless (defined $args{person}) {
	error( "didn't a person object name" );
    }
    unless (defined $args{name}) {
	error( "didn't get a mntner name" );
    }
    unless (defined $args{auth}) {
	error( "didn't get an auth param (PGPKEY-?)" );
    }
    unless (defined $args{descr}) {
	error( "didn't get a description" );
    }
    unless (defined $args{e_mail}) {
	error( "didn't get an email address" );
    }

    if (scalar @errors > 0) {
	return undef;
    }

    my $gen = Funknet::Whois::ObjectGenerator->new('source' => 'FUNKNET', 
						   'person' => $args{person} );
    
    my $me = $gen->mntner( 'name'   => $args{name}, 
			   'auth'   => $args{auth},
			   'descr'  => $args{descr}, 
			   'e_mail' => $args{e_mail} );
    unless (defined $me) {
	error("generating mntner: \n".$gen->error);
	return undef;
    } else {
	return $me;
    }
}

sub node_set {
    my (%args) = @_;

    # check args - we need: list of peers, the local network, mntner, and the name of the node
    
    unless (defined $args{peers} && scalar @{$args{peers}} > 0) {
	error( "didn't get a list of peers" );
    }
    unless (defined $args{network}) {
	error( "didn't get a network" );
    }
    unless (defined $args{mntner}) {
	error( "didn't get a mntner" );
    }
    unless (defined $args{nodename}) {
	error( "didn't get a nodename" );
    }
    unless (defined $args{endpoint}) {
	error( "didn't get an endpoint" );
    }

    if (scalar @errors > 0) {
	return undef;
    }
    
    my $ns;
    
    # check the requested local network is available
    
    my $inetnum = get_object('inetnum', "-x $args{network}");
    if (defined $inetnum) {
	error( "network is already taken" );
	return undef;
    }

    # check the endpoint looks valid

    unless (is_ipv4($args{endpoint})) {
	error( "invalid ipv4 address: $args{endpoint}" );
	return undef;
    }

    # check the specified peers exist
    my $peers;
    for my $peer (@{$args{peers}}) {
	$peers->{$peer} = get_object('aut-num', $peer);
	unless (defined $peers->{$peer}) {
	    error( "peer $peer doesn't exist in whois" );
	    return undef;
	}
    }
    
    # do objects for a node: tunnels/inetnums, aut-num, inetnum, route
    
    my $mntner = get_object('mntner', $args{mntner});
    unless (defined $mntner) {
	error( "mntner $args{mntner} doesn't exist" );
	return undef;
    }
    my $gen = Funknet::Whois::ObjectGenerator->new( 'source' => 'FUNKNET',
						    'mntner' => $args{mntner},
						    'person' => $mntner->admin_c,
						    'e_mail' => $mntner->upd_to,
						  );
    # get an AS number
    $ns->{as} = $gen->aut_num_assign( 'name'  => $args{nodename},
				      'descr' => $args{nodename},
				      'tuns'  => [ ],
				      'import' => [ ],
				      'export' => [ ],
				    );
    unless (defined $ns->{as}) {
	error("generating as: \n".$gen->error);
	return undef;
    }

    # generate tunnels - reset Policy first
    Funknet::Whois::Policy::reset_inums();
    
    my (@tun_names, @tun_inums, @tun_objs, @tun_as);
    for my $peer (@{$args{peers}}) {
	my $n = $args{nodename}.'-'.$peers->{$peer}->as_name;
	
	my $t_inetnum = $gen->inetnum_assign( 'name' => $n,
					      'peer' => $peer );
	unless (defined $t_inetnum) {
	    error("generating tunnel inetnum: \n".$gen->error);
	    return undef;
	}
	
	my $rtr = get_object_inverse('inet-rtr', 'local-as', $peer);
	unless (defined $rtr) {
	    error( "inet-rtr for $peer doesn't exist" );
	    return undef;
	}
	my $ifaddr = $rtr->ifaddr;
	$ifaddr =~ s/ MASKLEN.*$//;
	
	my $t = $gen->tunnel( 'name'     =>  $args{nodename}.'-'.$peers->{$peer}->as_name,
			      'as'       => [ $peers->{$peer}->aut_num,$ns->{as}->aut_num ],
			      'endpoint' => [ $ifaddr, $args{endpoint} ],
			      'address'  => [ $t_inetnum->tunnel_addresses ],
			      'type'     => 'ipip',
			    );
	if (defined $t) {
	    push @{$ns->{tun_objs}}, $t;
	    push @{$ns->{tun_inums}}, $t_inetnum;
	    push @tun_names, $n;
	    push @tun_as, $peers->{$peer}->aut_num;
	} else {
	    error("generating tunnel: \n".$gen->error);
	    return undef;
	}
    }
    
    $ns->{as}->tun(\@tun_names);
    
    # set up import and export policies on this AS
    
    my (@imports, @exports);
    for my $p (@tun_as) {
	push @imports, "from $p action pref=100; accept AS-FUNKTRANSIT and NOT ".$ns->{as}->aut_num;
	push @exports, "to $p announce ".$ns->{as}->aut_num;
    }
    $ns->{as}->ximport(\@imports); # ah man
    $ns->{as}->export(\@exports);
    
    $ns->{range} = $gen->inetnum('descr'   => $args{nodename}.' network',
				 'name'    => $args{nodename}.'-LAN',
				 'network' => $args{network} );
    unless (defined $ns->{range}) {
	error("generating local net inetnum: \n".$gen->error);
	return undef;
    }
    
    $ns->{route} = $gen->route( 'descr'    => $args{nodename},
				'origin'   => $ns->{as}->aut_num,
				'route'    => $args{network},
			      );
    unless(defined $ns->{route}) {
	error("generating local net route: \n".$gen->error);
	return undef;
    }
    return $ns;
    
}

sub error {
    my ($self, $err) = @_;
    if (defined $self && !ref $self) {
	$err = $self;
    }

    if (defined $err) {
	push @errors, "Tools::OG: $err";
    } else {
	my @this = @errors;
	@errors = ();
	return wantarray ? @this : join "\n", @this;
    }
}

1;
