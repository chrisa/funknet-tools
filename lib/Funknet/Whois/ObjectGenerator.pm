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

package Funknet::Whois::ObjectGenerator;
use strict;

=head1 NAME

Funknet::Whois::ObjectGenerator

=head1 DESCRIPTION

Routines for creating new objects for the whois db. 

Uses Funknet::Config::Whois::Policy.pm to decide how to assign new
addresses.  

We check for already existing objects, but we do not check for the
existence of referenced objects.

=head1 SYNOPSIS

  my $gen = Funknet::Whois::ObjectGenerator->new( 'mntner' => 'MY-MUNTER' );

  # we can now generate person objects

  my $me = $gen->person( 'name'    => 'A. N. Other',
                         'address' => 'Some Where',
                         'e_mail'  => 'me@example.com'
                       );

  # -- then --
  # send person object to whois...
  # -- later --

  my $gen = Funknet::Whois::ObjectGenerator->new( 'mntner'  => 'MY-MUNTER' 
                                                  'admin_c' => 'ANO1-FUNKNET',
                                                  'tech_c'  => 'ANO1-FUNKNET'
                                                );

  # we can now generate all types of object

  my $autnum = $gen->aut_num( 'name' => 'FOONET',
                              'as'   => undef,
                              'tuns' => [ 'FOO-CENTRAL1', 'FOO-CENTRAL2' ]
                            );

  my $tun = $gen->tunnel( 'name'    => 'FOO-CENTRAL1',
                          'as'      => ['AS65000','AS65001'],
                          'ep'      => ['1.2.3.4', '5.6.7.8'],
                          'addr'    => ['10.2.2.1', '10.2.2.2'],
                        );

  my $inetnum = $gen->inetnum( 'start' => '10.2.2.0',
                               'end'   => '10.2.2.3'
                             );

  my $range = $gen->inetnum( 'network' => '10.2.2.0/30' );

  my $route = $gen->route( 'name'    => 'FOOTUNNELS',
                           'origin'  => 'AS65000',
                           'network' => '10.2.0.0/24' );

=head1 METHODS

=head2 new( mntner =>  $mntner )

=head2 new( mntner => $mntner, admin_c => $person, tech_c => $person )

This returns a ObjectGenerator object. If you already have a
maintainer object, or person objects for the contacts, you can provide
them, but if not, the ObjectGenerator will only generate mntners or
persons.

=head2 aut_num( name => $name, as => $as, 
                tuns => [ $tun1, $tun2 ] )

This method generates aut-num objects. 

Given an AS number in $as, it will check it does not exist in the
database before returning an object; passed undef it will attempt to
allocate one according to the policy in Funknet::Whois::Policy.

Given a list of tunnel objects it will add those names as tun:
attributes.

=head2 inetnum ( name => $name, start => $start, end => $end )

=head2 inetnum ( name => $name, network => $cidr_net )

These methods generate inetnum objects. 

inetnum() expects start and end of range IP addresses as
dotted-decimal. inetnum_net() expects an IP network specified as a
CIDR network (x.x.x.x/a).

These methods will check that the inetnum object to be generated
does not exist in the database. They will *not* check for overlapping
ranges.

=head2 inetnum_assign ( name => $name, from => $range, size => $size)

This method will attempt to assign an new inetnum from an
already-existing inetnum range. The name specified must exist as an
inetnum, and the status of that inetnum must be 'ALLOCATED'.

The method will assign the next possible network, taking into
account IP subnet rules. It also takes into account the policy from
Funknet::Whois::Policy, which may limit the sizes of networks which
can be assigned in any particular range.

=head2 tunnel ( name => $name, as => [ $as1, $as2 ], 
                ep => [ $ep1, $ep2 ], addr => [ $ad1, $ad2 ] )

This method generates tunnel objects. 

The AS numbers, addresses and endpoints are taken directly from the
parameters passed in.

=head2 route ( name => $name, origin => $as, network => $network );

This method generates route objects. 

=head2 node_setup

This method generates a set of objects suitable for bootstrapping a
node. It needs the node name, the local networks to be advertised, the
mntner of the node, and the peer nodes.

It generates an aut-num, an inetnum for the local network (and the
corresponding route), tunnels to each peer (and the corresponding
inetnums). The maintainer should then sign the objects and send them
to the whois robot.

This method can fail if - the local network suggested is taken, the
mntner doesn't exist in the database, or if a valid set of peer nodes
is not specified (you need at least one valid peer node).

This method will generate aut-num objects with the relevant tun:
attributes, but the tunnels will not become active until the
maintainers of the peer nodes also add the tun: attributes to their
aut-num objects.

=cut

use Funknet::Config::Validate qw/ is_ipv4 is_valid_as / ;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    if defined ($args{mntner}) {
	$self->{mntner} = $args{mntner};
    }
    
    if defined ($args{admin_c}) {
	$self->{admin_c} = $args{admin_c};
    }
    if defined ($args{tech_c}) {
	$self->{tech_c} = $args{tech_c};
    }

    return $self;
}

sub mntner {
    my ($self, %args) = @_;

}

sub person {
    my ($self, %args) = @_;

    unless (defined $self->{mntner}) {
	return undef;
    }
    
    
}

sub aut_num {
    my ($self, %args) = @_;

}

sub inetnum {
    my ($self, %args) = @_;

}

sub inetnum_assign {
    my ($self, %args) = @_;

}

sub tunnel {
    my ($self, %args) = @_;

}

sub route {
    my ($self, %args) = @_;

}

sub node_setup {
    my ($self, %args) = @_;

}
