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

  
                        
      

=head1 METHODS

=head2 new($mntner, $admin_c, $tech_c)

This returns a ObjectGenerator object. If you already have a
maintainer object, or person objects for the contacts, you can provide
them, but if not, the ObjectGenerator will only generate mntners or
persons.

=head2 aut_num($name, $as, @tuns)

This method generates aut-num objects. 

Given an AS number in $as, it will check it does not exist in the
database before returning an object; passed undef it will attempt to
allocate one according to the policy in Funknet::Whois::Policy.

Given a list of tunnel objects it will add those names as tun:
attributes.

=head2 inetnum ($start, $end)

=head2 inetnum_net ($net)

These methods generate inetnum objects. 

inetnum() expects start and end of range IP addresses as
dotted-decimal. inetnum_net() expects an IP network specified as a
CIDR network (x.x.x.x/a).

These methods will check that the inetnum object to be generated
does not exist in the database. They will *not* check for overlapping
ranges.

=head2 inetnum_assign ($block_name, $size)

This method will attempt to assign an new inetnum from an
already-existing inetnum range. The name specified must exist as an
inetnum, and the status of that inetnum must be 'ALLOCATED'.

The method will assign the next possible network, taking into
account IP subnet rules. It also takes into account the policy from
Funknet::Whois::Policy, which may limit the sizes of networks which
can be assigned in any particular range.

=head2 tunnel ($name, $as1, $as2, $ep1, $ep2, $inetnum)

This method generates tunnel objects. 

The AS numbers and endpoints are taken directly from the parameters
passed in; the addresses are inferred from the inetnum (which may be
specified as $start - $end or $cidr as for the inetnum method).

=head2 route

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

