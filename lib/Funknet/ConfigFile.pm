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


package Funknet::ConfigFile;
use strict;
use vars qw/ $AUTOLOAD @ISA /;
use Carp qw/ cluck /;
use Funknet::Debug;
use Funknet::Config::Interactive;

=head1 NAME

Funknet::ConfigFile

=head1 SYNOPSIS

  my $config = Funknet::ConfigFile->new( $configfile, $interact_yn )

=head1 DESCRIPTION

An abstraction over a simple test config file. Syntax is:

    key = value
    key = value, value, value

    # Comment
    foo = bar  # comment

A repeated key causes the values to be added to the existing values
rather than overwriting them.

If you pass $interact_yn a true value and the file specified does not
exist, then the user will be prompted for the standard funknet.conf
params (see Interactive.pm).

If you want to just create a funknet.conf, call new with the config
file name, store some keys into it, then call write.

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

AUTOLOADed methods take params, and set them in the config hash. If
you pass one scalar value, it sets it. if you pass a list, it stores
it as an arrayref, if you pass an arrayref it just stores that.

=cut


my $config;

sub new {
    my ($class, $file, $interact) = @_;
    my $self = bless {}, $class;
    $self->{file} = $file;

    if (defined $config && ref $config eq 'HASH') {
        $self->{config} = $config;
        return $self;
    }

    debug("looking for config file '$file'");
    unless (-f $file) {
	if ($interact) {
	    # go interactive.
	    my $fci = new Funknet::Config::Interactive;
	    if (defined $fci) {
		$config = $fci->get_config;
		$self->{config} = $config;
		if (defined $self->{config}) {
		    $self->write;
		    return $self;
		} else {
		    $self->error("didn't get valid data from user in interactive-config mode");
		    return undef;
		}
	    } else {
		$self->error("interactive config requested but Term::Interact is not available");
	    }
	} else {
	    $self->warn("config file not found: $file");
	    return $self;
	}
    }
    debug("Reading config file '$file'");
    open CONF, $file
	or die "Can't open config file $file: $!";
    while (my $line = <CONF>) {
	chomp $line;
	next unless $line;
	next if $line =~ /^\s*(#|$)/; # ignore whitespace lines
	$line =~ s/#.*$//; # strip comments
        # ensure $key and $values split on the 1st '='
        if (my ($key, $values) = $line =~ /([^=]+)\s*=\s*(.+)/) {

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

    $self->validate_local_config();

    debug("Done parsing config file");
    return $self;
}

sub write {
    my ($self) = @_;
    debug("writing config file $self->{file}");
    
    open CONF, ">$self->{file}" 
      or die "couldn't open $self->{file} for writing: $!";
    print CONF "# config file written by $0 at ",scalar localtime,"\n";

    for my $key (sort keys %{ $self->{config} }) {
	
	if (ref $self->{config}->{$key}) {
	    print CONF "$key = ",join ', ',@{ $self->{config}->{$key} },"\n";
	} else {
	    print CONF "$key = $self->{config}->{$key}\n";
	}
    }
    close CONF;
}

sub warn {
    goto &Funknet::Config::warn;
}
sub error {
    goto &Funknet::Config::error;
}

sub AUTOLOAD {
    my ($self, @params) = @_;
    my $key = $AUTOLOAD;
    $key =~ s/.*::(.*)$/$1/;

    if (ref $self) {
	$config = $self->{config};
    }

    # if we have params, set the key. 
    if (ref $params[0] eq 'ARRAY') {
	$config->{$key} = $params[0];
    } elsif (defined $params[0] && defined $params[1]) {
	$config->{$key} = [ @params ];
    } elsif (defined $params[0]) {
	$config->{$key} = $params[0];
    } else {
	# don't set anything
    }

    # default 'halt' to 1 
    if ($key eq 'halt' && !exists $config->{halt}) {
	return 1;
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

sub get_config {
    return $config;
}

sub validate_local_config {
    # virtual
}

1;

