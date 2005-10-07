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

package Funknet::Whois::ObjectSyntax;
use strict;

use vars qw/ @EXPORT /;
@EXPORT = qw/ syntax /;
use base qw/ Exporter /;

sub syntax {

    my $syntax = {
                  'tunnel-type' => qr/^gre|ipip$/,

                  'filter-set'  => qr/^((AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|fltr-[A-Z0-9_-]*[A-Z0-9]):)*fltr-[A-Z0-9_-]*[A-Z0-9](:(AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|fltr-[A-Z0-9_-]*[A-Z0-9]))*$/,
          
                  irt => qr/^irt-[A-Z0-9_-]*[A-Z0-9]$/i,

                  'as-set' => qr/^((AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|as-[A-Z0-9_-]*[A-Z0-9]):)*as-[A-Z0-9_-]*[A-Z0-9](:(AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|as-[A-Z0-9_-]*[A-Z0-9]))*$/i,
              
                  'route-set' => qr/^((AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|rs-[A-Z0-9_-]*[A-Z0-9]):)*rs-[A-Z0-9_-]*[A-Z0-9](:(AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|rs-[A-Z0-9_-]*[A-Z0-9]))*$/i,
           
                  'peering-set' => qr/^((AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|prng-[A-Z0-9_-]*[A-Z0-9]):)*prng-[A-Z0-9_-]*[A-Z0-9](:(AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|prng-[A-Z0-9_-]*[A-Z0-9]))*$/i,
          
                  'rtr-set' => qr/^((AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|rtrs-[A-Z0-9_-]*[A-Z0-9]):)*rtrs-[A-Z0-9_-]*[A-Z0-9](:(AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|rtrs-[A-Z0-9_-]*[A-Z0-9]))*$/i,
          
                  'members-as' => qr/^((((AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|as-[A-Z0-9_-]*[A-Z0-9]):)*as-[A-Z0-9_-]*[A-Z0-9](:(AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])|as-[A-Z0-9_-]*[A-Z0-9]))*)|AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))$/,
              
                  'members-is' => sub {},

                  'members-rs' => sub {},
              
                  'mbrs-by-ref' => qr/^[A-Z]([A-Z0-9_-]*[A-Z0-9])?$/i,
              
                  'free-form' => undef,

                  'nic-handle' => qr/^(([A-Z]{2,4}[0-9]{0,6}(-[A-Z]([A-Z0-9_-]{0,7}[A-Z0-9]))?)|(AUTO-[0-9]+([A-Z]{2,4})?))$/i,
                                    
                  'object-name' => qr/^[A-Z]([A-Z0-9_-]*[A-Z0-9])?$/i,
           
                  'netname' => qr/^[A-Z]([A-Z0-9_-]*[A-Z0-9])?$/i,
           
                  'e-mail' => qr/^(([^][()<>,;:\\"[:space:]]+)|("[^"@\\]+"))@([A-Z0-9-]+(\.[A-Z0-9-]+)+)$/i,
           
                  'changed' => qr/^(([^][()<>,;:\\"[:space:]]+)|("[^"@\\]+"))@([A-Z0-9-]+(\.[A-Z0-9-]+)+)( [0-9]{8})?$/i,
           
                  filter => sub {},
              
                  'registry-name' => qr/^[A-Z]([A-Z0-9_-]*[A-Z0-9])?$/i,
           
                  'domain-name' => qr/^[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?(\.[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?)*$/i,
           
                  'subdomain-name' => qr/[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?(\.[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?)*$/i,
           
                  'ipv4-address' => qr/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/,
           
                  refer => sub {},
              
                  'person-name' => qr/^[A-Z]([A-Z0-9.`'_-]*[A-Z0-9`'_-])?([[:space:]]+[A-Z0-9.`'_-]+)*[[:space:]]+[A-Z]([A-Z0-9.`'_-]*[A-Z0-9`'_-])?$/i,
              
                  'telephone-number' => qr/^\+[[:space:]]*[0-9][0-9.[:space:]-]*(\([0-9.[:space:]-]*[0-9][0-9.[:space:]-]*\))?([0-9.[:space:]-]*[0-9][0-9.[:space:]-]*)?([[:space:]]+ext.[0-9.[:space:]-]*[0-9][0-9.[:space:]-]*)?$/i,
           
                  'auth-scheme' => qr/^(NONE|CRYPT-PW [A-Z0-9.\/]{13}|MD5-PW \$1\$[A-Z0-9.\/]{1,8}\$[A-Z0-9.\/]{22}|PGPKEY-[A-F0-9]{8})$/,
              
                  inetnum => qr/^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])) - ((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$/,
              
                  inet6num => sub {},
              
                  'country-code' => qr/^[A-Z]{2}$/,

                  'status' => qr/^((ALLOCATED (PA|PI|UNSPECIFIED))|((ASSIGNED|LIR-PARTITIONED) (PA|PI)))$/,
           
                  'status-i6' => qr/^(ALLOCATED-BY-RIR|ALLOCATED-BY-LIR|ASSIGNED)$/,
           
                  'mnt-routes' => qr/^[A-Z]([A-Z0-9_-]){1,80}([[:space:]]+.*)*$/i,
          
                  'public-key' => sub {},

                  fingerpr => qr/^(([A-F0-9]{4} ){9}[A-F0-9]{4})|(([A-F0-9]{2} ){15}[A-F0-9]{2})$/i,
           
                  'key-cert' => qr/^(PGPKEY-[A-F0-9]{8}|X509CERT-[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2})$/i,
           
                  'address-prefix' => qr/^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\/([12]?[0-9]|3[012])$/,
           
                  'as-number' => qr/^AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-4])$/,
              
                  'as-block' => qr/^AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-4]) - AS([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-4])$/,
           
                  limerick => qr/^lim-[A-Z0-9_-]*$/i,
          
                  components => sub {},
             
                  'aggr-mtd' => sub {},
              
                  'aggr-bndry' => sub {},

                  default => sub {},

                  export => sub {},

                  import => sub {},

                  ifaddr => sub {},

                  inject => sub {},

                  peering => sub {},

                  peer => sub {},

                  'referral-by' => sub {},

                 };

    return $syntax;
}
