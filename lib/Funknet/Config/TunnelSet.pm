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


package Funknet::Config::TunnelSet;
use strict;
use base qw/ Funknet::Config /;

=head1 NAME

Funknet::Config::TunnelSet

=head1 DESCRIPTION

Provides a collection object for Tunnels. Contains the ->diff method
for tunnels. 

=head1 METHODS

=head2 new(source => 'whois', tunnels => \@tuns)

Takes the source and a listref of Tunnels. 

=head2 diff($hostobj)

Called on a TunnelSet object of source whois and passed a TunnelSet
object of source host, returns the commands required to update the
host's tunnel config to that specified in the whois.

=head1 TODO

It should probably be possible to add Tunnels via a method, rather
than all at once by passing the constructor a listref.

If we destroy interfaces, we should probably reuse the numbering.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    $self->{_tunnels} = $args{tunnels};
    $self->{_source} = $args{source};
    
    return $self;
}

sub tunnels {
    my ($self) = @_;
    return @{$self->{_tunnels}};
}

sub config {
    my ($self) = @_;

    my @cmds;
    my $i = 0;
    for my $tun ($self->tunnels) {
        push @cmds, $tun->create($i);
	$i++;
    }
    return @cmds;
}

sub source {
    my ($self) = @_;
    return $self->{_source};
}

sub diff {
    my ($whois, $host) = @_;
    my (@cmds, $if_num);
    $if_num = 0;

    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
	$whois->warn("diff passed objects backwards");
	return undef;
    }    
    
    # create hashes

    my ($whois_tuns, $host_tuns);
    for my $tun ($whois->tunnels) {
	$whois_tuns->{$tun->as_hashkey} = 1;
    }
    for my $tun ($host->tunnels) {
	$host_tuns->{$tun->as_hashkey} = 1;
	# keep track of interface numbering
	if ($tun->interface > $if_num) {
	    $if_num = $tun->interface;
	}
    }

    for my $h ($host->tunnels) {
	unless ($whois_tuns->{$h->as_hashkey}) {
	    push @cmds, $h->delete;
	}
    }

    my @ignore_if = (Funknet::Config::ConfigFile->ignore_if, map {$_->ifname} $host->tunnels);

    for my $w ($whois->tunnels) {
	unless ($host_tuns->{$w->as_hashkey}) {
	    my $if_sym = $w->ifsym;
	    while ( scalar( grep /$if_sym$if_num/, @ignore_if ) >0 ) {
		$if_num++;
	    }
	    push @cmds, $w->create($if_num);
	    $if_num++;
	}
    }
    return @cmds;
}

1;
