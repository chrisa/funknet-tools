package Funknet::Config::Tunnel;
use strict;
use Funknet::Config::Validate qw/ is_ipv4 is_ipv6 is_valid_type /;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'ifconfig')) {
	warn "missing source";
	return undef;
    } else {
	$self->{_source} = $args{source};
    }

    unless (defined $args{type} && is_valid_type($args{type})) {
	warn "missing or invalid type: $args{type}";
	return undef;
    } else {
	$self->{_type} = $args{type};
    }
    
    if ($self->{_type} eq 'sit') {
	$self->{_proto} = 'IPv6';
    } else {
	$self->{_proto} = 'IPv4';
    }
    
    if ($self->{_proto} eq 'IPv4') {
	for my $addr (qw/ local_address remote_address local_endpoint remote_endpoint / ) {
	    unless (is_ipv4 ($args{$addr})) {
		warn "invalid ipv4 address: $addr";
		return undef;
	    } else {
		$self->{"_$addr"} = $args{$addr};
	    }
	} 
    } elsif ($self->{_proto} eq 'IPv6') {
	for my $addr (qw/ local_address remote_address / ) {
	    unless (is_ipv6 ($args{$addr})) {
		warn "invalid ipv6 address: $addr";
		return undef;
	    } else {
		$self->{"_$addr"} = $args{$addr};
	    }
	}
	for my $addr (qw/ local_endpoint remote_endpoint / ) {
	    unless (is_ipv4 ($args{$addr})) {
		warn "invalid ipv4 address: $addr";
		return undef;
	    } else {
		$self->{"_$addr"} = $args{$addr};
	    }
	}
    }
    return $self;
}

sub as_string {
    my ($self) = @_;
    
    return 
	"$self->{_type}:\n" .
	"$self->{_local_endpoint} -> $self->{_remote_endpoint}\n" . 
	"$self->{_local_address} -> $self->{_remote_address}\n";
}

1;
