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
use Funknet::Whois qw/ get_object /;
use Funknet::Whois::ObjectGenerator;

use Data::Dumper;

# error buffer.
our @errors;

=head1 DESCRIPTION

Reasonable interface to the Funknet::Whois::ObjectGenerator stuff.

=cut

sub node_set {
    my (%args) = @_;

    @errors = ();

    # check args - we need: list of peers, the local network, mntner, and the name of the node
    
    unless (defined $args{peers}) {
	error( "didn't get a list of peers" );
	return undef;
    }
    unless (defined $args{network}) {
	error( "didn't get a network" );
	return undef;
    }
    unless (defined $args{mntner}) {
	error( "didn't get a mntner" );
	return undef;
    }
    unless (defined $args{nodename}) {
	error( "didn't get a nodename" );
	return undef;
    }

    my $ns;
    
    # check the requested local network is available
    
    my $inetnum = get_object('inetnum', "-x $args{network}");
    if (defined $inetnum) {
	error( "network is already taken" );
	return undef;
    }
    
    # check the specified peers exist
    my $peers;
    for my $peer (@{$args{peers}}) {
	$peers->{$peer} = get_object('aut-num', $peer);
	unless (defined $peers->{$peer}) {
	    error( "peer $peer doesn't exist" );
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
    # generate tunnels
    
    my (@tun_names, @tun_inums, @tun_objs, @tun_as);
    for my $peer (@{$args{peers}}) {
	my $n = $args{nodename}.'-'.$peers->{$peer}->as_name;
	
	my $t_inetnum = $gen->inetnum_assign( 'name'    => $n,
					      'purpose' => 'tunnel' );
	
	my $t = $gen->tunnel( 'name'    =>  $args{nodename}.'-'.$peers->{$peer}->as_name,
			      'as'      => [$peers->{$peer}->aut_num,$ns->{as}->aut_num],
			      'endpoint'      => ['',''],
			      'address'    => ['',''],
			      'type'    => 'ipip',
			    );
	if (defined $t) {
	    push @{$ns->{tun_objs}}, $t;
	    push @{$ns->{tun_inums}}, $t_inetnum;
	    push @tun_names, $n;
	    push @tun_as, $peers->{$peer}->aut_num;
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
    
    $ns->{range} = $gen->inetnum('name' => $args{nodename}.'-LAN',
				 'network' => $args{network} );
    
    $ns->{route} = $gen->route( 'descr'    => $args{nodename},
				'origin'   => $ns->{as}->aut_num,
				'route'    => $args{network},
			      );
    return $ns;
    
}

sub error {
    my ($err) = @_;

    if (defined $err) {
	push @errors, $err;
    } else {
	return wantarray ? @errors : join "\n", @errors;
    }
}

1;
