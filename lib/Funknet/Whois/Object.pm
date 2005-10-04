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

package Funknet::Whois::Object;
use strict;
use Funknet::Whois::ObjectDefs;
use DateTime::Format::W3CDTF;

use vars qw/ $AUTOLOAD /;

=head1 NAME

Funknet::Whois::Object

=cut

sub new {
    my ($class, $text, %args) = @_;
    my $self = bless {}, $class;

    my $f;
    if ($args{TimeStamp}) {
        $f = DateTime::Format::W3CDTF->new;
    }
    
    $self->{_content} = [];
    my $key;

  LINE:
    for my $line (split /\r?\n/, $text) {

        # is this a continuation line?
        # first, have we seen any keys?
        if (defined $self->{_order}) {
            if ($line =~ s/^(\+\s?|\s)//) {
                ${ $self->{_methods}->{$key} }[-1] .= " $line";
                ${ $self->{_content} }[-1] .= " $line";
                next LINE;
            }
        }

        ($key, my $val) = $line =~ /(.+?):\s*(.+)?/;
	next unless ($key);
	if (!defined $val) { $val = "" };
	push @{ $self->{_methods}->{$key} }, $val;
	push @{ $self->{_content} }, $val;
	
	my $test = ${ $self->{_order} }[-1] || 0;
	if ($test ne $key) {
	    push @{ $self->{_order} }, $key;
	}

        if ($args{TimeStamp} && $key eq 'timestamp') {
            if ($val eq '') {
                return;
            }
            my $dt;
            eval {
                $dt = $f->parse_datetime($val);
            };
            if ($@) {
                return;
            } else {
                $val = $f->format_datetime($dt);
                $self->{_epoch_time} = $dt->epoch;
            }
        }
    }

    if (scalar @{ $self->{_content} } > 0) {
	return $self->validate();
    } else {
	return;
    }
}

sub error {
    my ($self, $errortext) = @_;
    if (defined $errortext) {
	$self->{_updater_errortext} .= "$errortext\n";
    }
    $errortext = $self->{_updater_errortext};
    $errortext =~ s/\n?$//;
    return $errortext;
}

sub object_type {
    my ($self) = @_;
    return $self->{_order}->[0];
}

sub object_name {
    my ($self) = @_;
    return $self->{_content}->[0];
}

sub AUTOLOAD {
    my ($self, $new) = @_;

    my $name = $AUTOLOAD;
    $name =~ s/.*://;   # strip fully-qualified portion
    $name =~ s/_/-/;    # change _ to - in method name: same as 'add'
    $name =~ s/^x//;    # strip x off the front so we can call import
    
    unless (exists $self->{_methods}->{$name} ) {
	return undef;
    }
    
    if (defined $new) {
	if (ref $new eq 'ARRAY') {
	    $self->{_methods}->{$name} = $new;
	} else {
	    $self->{_methods}->{$name} = [ $new ];
	}
    }

    return wantarray 
      ? @{$self->{_methods}->{$name}}
	: $self->{_methods}->{$name}->[0];
}

sub DESTROY {}

sub text {
    my ($self) = @_;

    my @lines;
    my $maxkey = 0;

    my @content;
    for my $method (@{ $self->{_order} }) {
	next unless $self->{_methods}->{$method}->[0]; 
	push @content, map { $method.':    '.$_ } @{ $self->{_methods}->{$method} };
    }

    for my $line (@content) {
	my ($key, $val) = $line =~ /([a-zA-Z-]+?):\s*(.+)/;
	push @lines, { key => $key, val => $val };
	if (length $key > $maxkey) {
	    $maxkey = length $key;
	}
    }
    my $text = '';
    for my $line (@lines) {
	$text .= $line->{key} . ':    ' . (' ' x ($maxkey - length $line->{key})) . $line->{val} . "\n";
    }
    
    # delete trailing spaces, so they don't get QP-ed 
    # applies to key-cert: mostly.
    $text =~ s/ +$//g;

    return wantarray 
	? @content 
	: $text;
}

sub tunnel {
    my ($self) = @_;
    $self->{_tunnel} = 1;
}

=head2 tunnel_addresses

Returns the two usable addresses in a /30, assuming ->tunnel has
already been called.

=cut

sub tunnel_addresses {
    my ($self) = @_;
    return undef unless $self->{_tunnel};
    
    my $inetnum = $self->inetnum;
    my ($network, $octet) = $inetnum =~ /(\d+\.\d+\.\d+\.)(\d+) -/;
    return undef unless defined $network && defined $octet;

    # we get away with this, because this inetnum *must* be a /30,
    # and this hack is always valid for a /30.
    return ( ($network . ($octet+1)) , ($network . ($octet+2)) );
}

=head2 rawtext

Returns the raw key material from a key-cert object.

=cut

sub rawtext {
    my ($self) = @_;
    return undef unless $self->{_methods}->{'key-cert'};

    my $key = join "\n",$self->certif;
    $key .= "\n";
    $key =~ s/^certif: //;
    return $key;
}

=head2 epoch_time

Returns the object's timestamp in epoch (unix) time seconds.

=cut

sub epoch_time {
    my ($self) = @_;
    return $self->{_epoch_time};
}

=head2 validate

Validates the object according to the ObjectDefs file. Returns the
object, with error() set to the problems found.

=cut

sub validate {
    my ($self) = @_;
    my $t = Funknet::Whois::ObjectDefs::objectdefs();
    
    # check for type, retrieve known object's def. 
    my $def = $t->{$self->object_type};
    unless ($def) {
        $self->error("Unknown object type: ". $self->object_type());
        return $self;
    }
    
    # check for all mandatory keys
    my @missing;
    for my $key (sort grep { $def->{$_}->{mandatory} eq 'mandatory' } keys %$def) {
        if (!exists $self->{_methods}->{$key}) {
            push @missing, $key;
        }
    }
    if (scalar @missing > 1) {
        $self->error("Missing mandatory attributes: ".( join ', ',@missing ));
    }
    if (scalar @missing == 1) {
        $self->error("Missing mandatory attribute: ".$missing[0]);
    }

    # check for 'unique' keys used more than once
    my @used;
    for my $key (sort grep { $def->{$_}->{count} eq 'single' } keys %$def) {
        if (exists $self->{_methods}->{$key}) {
            if (scalar @{$self->{_methods}->{$key}} > 1) {
                push @used, $key;
            }
        }
    }
    if (scalar @used > 1) {
        $self->error("Unique attributes ".( join ', ',@used )." used multiple times");
    }
    if (scalar @used == 1) {
        $self->error("Unique attribute ".$used[0]." used multiple times");
    }
    
    # check for keys not in the definition
    my @unknown;
    for my $attr (sort keys %{$self->{_methods}}) {
        unless (exists $def->{$attr} || $attr eq $self->object_type()) {
            push @unknown, $attr;
        }
    }
    if (scalar @unknown > 1) {
        $self->error("Unknown attributes ".( join ', ',@unknown ));
    }
    if (scalar @unknown == 1) {
        $self->error("Unknown attribute ".$unknown[0]);
    }

    return $self;
} 

1;
