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


package Funknet::Config::Neighbor;
use strict;
use Funknet::Config::Validate qw/ is_ipv4 /;

use base qw/ Funknet::Config /;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'host')) {
	$self->warn("missing source");
	return undef;
    } else {
	$self->{_source} = $args{source};
    }

    unless (defined $args{remote_as}) {
	$self->warn("missing remote_as");
	return undef;
    } else {
	my $asno = $args{remote_as};
	$asno =~ s/^AS//;
	$self->{_remote_as} = $asno;
    }

    unless (defined $args{remote_addr}) {
	$self->warn("missing remote_addr");
	return undef;
    } else {
	$self->{_remote_addr} = $args{remote_addr};
    }

    if (defined $args{description}) {
	$self->{_description} = $args{description};
    }

    if (defined $args{acl_in}) {
	$self->{_acl_in} = $args{acl_in};
    }
    if (defined $args{acl_out}) {
	$self->{_acl_out} = $args{acl_out};
    }

    return $self;
}

sub config {
    my ($self) = @_;

    my @cmds;
    push @cmds, "neighbor $self->{_remote_addr} remote-as $self->{_remote_as}";
    if (defined $self->{_description}) {
        push @cmds, "neighbor $self->{_remote_addr} description $self->{_description}";
    }
    if (defined $self->{_acl_in}) {
	push @cmds, "neighbor $self->{_remote_addr} route-map ".($self->{_acl_in}->name)." in";
    }
    if (defined $self->{_acl_out}) {
	push @cmds, "neighbor $self->{_remote_addr} route-map ".($self->{_acl_out}->name)." out";
    }
    return @cmds;
}

sub diff {
    my ($whois, $host) = @_;
    my @cmds;

    unless ($whois->remote_as == $host->remote_as) {
	# change of as - delete, restart from scratch.
	push @cmds, "no neighbor ".$host->remote_addr;
	push @cmds, $whois->config;
    }

    unless ($whois->description eq $host->description) {
	push @cmds, "neighbor ".$whois->remote_addr." description ".$whois->description;
    }
    
    if (defined $whois->{_acl_in}) {
	if (defined $host->{_acl_in}) {
	    # both exist, check they're the same
	    unless ($whois->{_acl_in}->name eq $host->{_acl_in}->name) {
		push @cmds, "neighbor ".$whois->remote_addr." route-map ".$whois->{_acl_in}->name." in";
	    }
	} else {
	    # nothing in host, but whois exists: add.
	    push @cmds, "neighbor ".$whois->remote_addr." route-map ".$whois->{_acl_in}->name." in";
	}
    } else {
	if (defined $host->{_acl_in}) {
	    # host has acl, but it's not in whois: delete
	    push @cmds, "no neighbor ".$host->remote_addr." route-map ".$host->{_acl_in}->name." in";
	}
    }
    
    if (defined $whois->{_acl_out}) {
	if (defined $host->{_acl_out}) {
	    # both exist, check they're the same
	    unless ($whois->{_acl_out}->name eq $host->{_acl_out}->name) {
		push @cmds, "neighbor ".$whois->remote_addr." route-map ".$whois->{_acl_out}->name." out";
	    }
	} else {
	    # nothing in host, but whois exists: add.
	    push @cmds, "neighbor ".$whois->remote_addr." route-map ".$whois->{_acl_out}->name." out";
	}
    } else {
	if (defined $host->{_acl_out}) {
	    # host has acl, but it's not in whois: delete
	    push @cmds, "no neighbor ".$host->remote_addr." route-map ".$host->{_acl_out}->name." out";
	}
    }

    return @cmds;
}

# accessors

sub remote_addr {
    my ($self) = @_;
    return $self->{_remote_addr};
}
sub remote_as {
    my ($self) = @_;
    return $self->{_remote_as};
}
sub description {
    my ($self) = @_;
    return $self->{_description};
}

1;
