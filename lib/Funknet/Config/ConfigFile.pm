#!/usr/bin/perl -w
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


package Funknet::Config::ConfigFile;
use strict;
use vars qw/ $AUTOLOAD @ISA /;
use Carp qw/ cluck /;
use Funknet::Config::Validate qw / is_ipv4 is_ipv6 is_valid_as is_valid_router is_valid_os /;
use Funknet::Debug;

=head1 NAME

Funknet::Config::ConfigFile

=head1 SYNOPSIS

  my $config = Funknet::Config::ConfigFile->new( $configfile )

=head1 DESCRIPTION

An abstraction over a simple test config file. Syntax is:

    key = value
    key = value, value, value

    # Comment
    foo = bar  # comment

A repeated key causes the values to be added to the existing values
rather than overwriting them.

=head1 METHODS

=head2 new

Call with one arg of the full path to the config file. Returns a
config object which you can use to access keys. 

=head2 AUTOLOAD

To retrieve a key, call ->key on the ConfigFile object, or as a class
method. Multi-value key semantics: called in scalar context, returns
the value, or the first value of a list. Called in list context,
returns either the list or just the one value. Never returns a
reference.

=cut


my $config;

sub new {
    my ($class, $file) = @_;
    my $self = bless {}, $class;
    debug("Reading config file '$file'");
    open CONF, $file
	or die "Can't open config file $file: $!";
    while (my $line = <CONF>) {
	chomp $line;
	next unless $line;
	next if $line =~ /^\s*(#|$)/; # ignore whitespace lines
	$line =~ s/#.*$//; # strip comments
        if (my ($key, $values) = $line =~ /(.+)\s*=\s*(.+)/) {

	    # Ignore whitespace
 	    $key =~ s/^\s+//;
	    $key =~ s/\s+$//;
	    $values =~ s/^\s+//;
	    $values =~ s/\s+$//;
	
	    if (exists $config->{$key}) {
		# Add value to existing key
		my @values;
		if ($values =~ /,/) {
		    @values = split /\s*,\s*/,$values;
		} else {
		    @values = ($values);
		}
		if (ref $config->{$key} eq 'ARRAY') {
		    push @{ $config->{$key} }, @values;
		} else {
		    $config->{$key} = [ $config->{$key}, @values ];
		}
	    } else {
		# Make new key
		if ($values =~ /,/) {
		    $config->{$key} = [ split /\s*,\s*/,$values ];
		} else {
		    $config->{$key} = $values;
		}
	    }
	}
    }
    debug("Closing config file");
    close CONF;

    debug("Parsing config file");
    $self->{config} = $config;

    if (defined $config->{debug} && $config->{debug}==1) {
	$Funknet::Config::DEBUG = 1;
    }

    debug("Testing local_as");
    unless (defined $config->{local_as} && is_valid_as($config->{local_as})) {
	$self->warn("missing or invalid 'local_as' in $file");
	return undef;
    } 

    debug("Testing local_host");
    unless (defined $config->{local_host} && is_ipv4($config->{local_host})) {
	$self->warn("missing or invalid 'local_host' in $file");
	return undef;
    } 

    debug("Testing local_endpoint");
    unless (defined $config->{local_endpoint} && is_ipv4($config->{local_endpoint})) {
	$self->warn("missing or invalid 'local_endpoint' in $file");
	return undef;
    }

    debug("Testing local_router");     
    unless (defined $config->{local_router} && is_valid_router($config->{local_router})) {
	$self->warn("missing or invalid 'local_router' in $file");
	return undef;
    } 

    debug("Testing local_os");
    unless (defined $config->{local_os} && is_valid_os($config->{local_os})) {
	$self->warn("missing or invalid 'local_os' in $file");
	return undef;
    } 

    debug("Done parsing config file");
    return $self;
}

sub local {
    my ($self) = @_;
    if (ref $self) {
	$config = $self->{config};
    }
    
    return { as     => $config->{local_as},
	     os     => $config->{local_os},
	     host   => $config->{local_host},
	     router => $config->{local_router},
	     endpoint => $config->{local_endpoint},
	   };
}
    
sub warn {
    goto &Funknet::Config::warn;
}
sub error {
    goto &Funknet::Config::error;
}

sub AUTOLOAD {
    my ($self) = @_;
    my $key = $AUTOLOAD;
    $key =~ s/Funknet::Config::ConfigFile:://;
    if (ref $self) {
	$config = $self->{config};
    }
	
    if (exists $config->{$key}) { 
	if (ref $config->{$key}) {
	    if (wantarray) {
		return @{ $config->{$key} };
	    } else {
		return $config->{$key}->[0];
	    }
	} else {
	    return $config->{$key};
	}
    } else {
	CORE::warn "accessing non-existent param $key";
	return undef;
    }
}

sub DESTROY {};

1;
