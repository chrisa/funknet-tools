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


package Funknet::Config::AccessList;
use strict;
use base qw/ Funknet::Config /;

=head1 NAME

Funknet::Config::AccessList

=head1 SYNOPSIS
    
    my $acl_in = Funknet::Config::AccessList->new( source_as   => 'AS65000',
                                                   peer_as     => 'AS65002',
                                                   source_addr => '10.2.0.37'
                                                   peer_addr   => '10.2.0.38'
                                                   dir         => 'import',
                                                   source      => 'whois',
						 );

    -- or --
    
    my $acl_in = Funknet::Config::AccessList->new( source_as   => 'AS65000',
                                                   peer_as     => 'AS65002',
                                                   source_addr => '10.2.0.37',
                                                   peer_addr   => '10.2.0.38',
					           dir         => 'import',
					           source      => 'host',
						 );


    my $acl_in_name = $acl_in->name;
    my $configtext = $acl_in->config;

=head1 DESCRIPTION

This module encapsulates both IP prefix-lists and the related
route-maps for BGP neighbors. There is a 1-1 relationship between
route-maps, prefix-lists and neighbors. The generic term 'Access List'
is used because it is intended to expand this module to cover IP
packet-filtering access lists.

Tne access lists are not broken down into a detailed representation as
objects, just the 'text' of the list is stored, and the name. The
module can create access-list objects from both the whois database and
the running host. Because enable mode is avoided we cannot just copy
the access list text as the router stores it but must translate the
'sho ip prefix-list' output into the 'configuration commands'
representation. (todo: this)

Our diff method is called when the Neighbor code detects that both the
Host and Whois configuration have an route-map set. In this case, the
text of the access-list is compared and if different, replaced by the
Whois version. 

=head1 METHODS

=head2 new

This method takes the details required to call the IRRToolSet RtConfig
program, or the details required to extract the same information from
the host, as well as the 'source' argument. 

If 'source' is 'whois', the private method _get_whois is called, which
is the wrapper around RtConfig. If 'source' is 'host' the appropriate
router-specific method is called via the CLI module.

=head2 config

Returns the configuration required to add the access-list and
route-map to the router's configuration. Assumes these do not already
exist.

=head2 diff

Called on an AccessList object with a source of 'whois' and an
argument of an AccessList object with a source of 'host', this method
returns the configuration commands required to remove and replace (or
amend, maybe) the access-list and route-map referenced by the Host
with the one in the Whois object.

=cut

sub new {
    my ($class, %args) = @_;

    $args{source_as} =~ s/^AS//;
    $args{peer_as} =~ s/^AS//;

    $args{source_as} =~ /^\d+$/ or return undef;
    $args{peer_as}   =~ /^\d+$/ or return undef;
    if ($args{source} eq 'whois') {
	$args{source_addr} =~ /^\d+\.\d+\.\d+\.\d+$/ or return undef;
    }
    $args{peer_addr}   =~ /^\d+\.\d+\.\d+\.\d+$/ or return undef;
    $args{dir}      =~ /^(import|export)$/ or return undef;
    
    if ($args{source} eq 'whois') {
	my $self = _get_whois(%args);
	if (defined $self) {
	    return bless $self, $class;
	} else {
	    return undef;
	}
    }
    if ($args{source} eq 'host') {
	my $cli = Funknet::Config::CLI->new();
	my $self = $cli->get_access_list( remote_addr => $args{peer_addr},
					  dir => $args{dir} );
	if (defined $self) {
	    $self->{_source} = 'host';
	    return bless $self, $class;
	} else {
	    return undef;
	}
    }
    return undef;
}

sub _get_whois {
    my (%args) = @_;

    my $rtconfig_path = Funknet::ConfigFile::Tools->rtconfig_path;
    my $host = Funknet::ConfigFile::Tools->whois_host || 'whois.funknet.org';
    my $port = Funknet::ConfigFile::Tools->whois_port || 43;
    my $source = Funknet::ConfigFile::Tools->whois_source || 'FUNKNET';

    # if it's not there, just return undef;
    unless (-x $rtconfig_path) { 
	return undef;
    }
    
    my $rtconfig = 
	$rtconfig_path . " -h $host -p $port -s $source -protocol ripe " . 
	'-config cisco -cisco_use_prefix_lists';

    my $command = 
	'@RtConfig '.$args{dir}.' AS'.$args{source_as}.' '.$args{source_addr}.' AS'.
	$args{peer_as}.' '.$args{peer_addr}."\n";

    my @output = `echo '$command' | $rtconfig`;
    
    my $acl_text = '';
    my $acl_name;
    for my $line (@output) {
	next unless ($line =~ /^ip prefix-list/);
	$acl_name = $args{peer_as}.$args{dir};
	$line =~ s/pl100/$acl_name/;
	$acl_text .= $line;
    }
    
    my $acl;
    if (length $acl_text) {
	$acl->{_acl_text} = $acl_text;
	$acl->{_name} = $acl_name;
	$acl->{_source} = 'whois';
	return $acl;
    } else {
	return undef;
    }
}

sub name {
    my ($self) = @_;
    return $self->{_name};
}

sub text {
    my ($self) = @_;
    return $self->{_acl_text};
}

sub source {
    my ($self) = @_;
    return $self->{_source};
}

sub config {
    my ($self) = @_;
    my @cmds;
    push @cmds, $self->{_acl_text};
    push @cmds, "route-map $self->{_name} permit 1", "match ip address prefix-list $self->{_name}";
    return @cmds;
}

sub diff {
    my ($whois, $host) = @_;
    my @cmds;

    # XXX 
    # this is really simplistic - we don't attempt to see if
    # we can just modify the access-list and use soft-reconfig

    # first check we have the objects the right way around.
    unless ($whois->source eq 'whois' && $host->source eq 'host') {
	$whois->warn("diff passed objects backwards");
	return undef;
    }    

    # if the access-lists have different names, then just remove 
    # the old one and replace it.

    if ($whois->name ne $host->name) {
	push @cmds, "no route-map ".$host->name;
	push @cmds, "no ip prefix-list ".$host->name;
	push @cmds, $whois->config;
	push @cmds, 'exit';
	return @cmds;
    }

    # if the access-lists are different, remove and replace.

    if ($whois->text ne $host->text) {
	push @cmds, "no route-map ".$host->name;
	push @cmds, "no ip prefix-list ".$host->name;
	push @cmds, $whois->config;
	push @cmds, 'exit';
	return @cmds;
    }
    return undef;
}

1;
