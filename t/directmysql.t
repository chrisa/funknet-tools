#!/usr/local/bin/perl -w
#
# $Id$
#
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

use strict;
use Test::More tests => 11;

BEGIN { use_ok ( 'Funknet::Whois::DirectMysql' ); }

# testing ipv4_to_int

is (Funknet::Whois::DirectMysql::ipv4_to_int('0.0.0.0'),         0, '0.0.0.0');
is (Funknet::Whois::DirectMysql::ipv4_to_int('255.255.255.255'), 4294967295, '255.255.255.255');
is (Funknet::Whois::DirectMysql::ipv4_to_int('62.169.139.122'),  1051298682, '62.169.139.122');

is (Funknet::Whois::DirectMysql::ipv4_to_int('255.255.255.256'), undef, '255.255.255.256');
is (Funknet::Whois::DirectMysql::ipv4_to_int('-1.0x45.foo.1'), undef, 'gibberish');

# testing int_to_ipv4

is (Funknet::Whois::DirectMysql::int_to_ipv4('0'),          '0.0.0.0',        '0.0.0.0');
is (Funknet::Whois::DirectMysql::int_to_ipv4('4294967295'), '255.255.255.255','255.255.255.255');
is (Funknet::Whois::DirectMysql::int_to_ipv4('1051298682'), '62.169.139.122', '62.169.139.122');

is (Funknet::Whois::DirectMysql::int_to_ipv4('-1'), undef, 'int -1');
is (Funknet::Whois::DirectMysql::int_to_ipv4('9999999999'), undef, 'int 9999999999');

