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


package Funknet::Tools::RtConfig;
use strict;

our @errors;

=head1 DESCRIPTION

A wrapper around RIPE's RtConfig tool. 

=cut

sub rtconfig {
    my (%args) = @_;
    
    my $rtconfig = 
      '/usr/local/bin/RtConfig -h whois.funknet.org -p 43 -s FUNKNET -protocol ripe ' . 
	'-config cisco -cisco_use_prefix_lists';
	
    $args{sourceas} =~ /^AS\d+$/ or error("Source AS must resemble ASxxxxx");
    $args{peeras}   =~ /^AS\d+$/ or error("Peer AS must resemble ASxxxxx");
    $args{sourcert} =~ /^\d+\.\d+\.\d+\.\d+$/ or error("Source router must be an IPv4 address");
    $args{peerrt}   =~ /^\d+\.\d+\.\d+\.\d+$/ or error("Peer router must be an IPv4 address");
    $args{dir}      =~ /^(import|export)$/ or error("Direction must be \'import\' or \' export\'");
	
    if (error()) {
	return undef;
    }
	
    my $command = 
      '@RtConfig '.$args{dir}.' '.$args{sourceas}.' '.$args{sourcert}.' '.
	$args{peeras}.' '.$args{peerrt}."\n";
	
    my $result = `echo '$command' | $rtconfig`;

    if (defined $result) {
	return $result;
    } else {
	error("no output from rtconfig");
	return undef;
    }
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
