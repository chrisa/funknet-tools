package Funknet::Config::Tunnel;
use strict;
use Funknet::Config::Validate qw/ is_ipv4 is_ipv6 is_valid_type /;

use Funknet::Config::Tunnel::BSD;
use Funknet::Config::Tunnel::IOS;
use Funknet::Config::Tunnel::Linux;
use Funknet::Config::Tunnel::Solaris;

sub new {
    my ($class, %args) = @_;
    my $self = bless {}, $class;

    unless (defined $args{source} && ($args{source} eq 'whois' || $args{source} eq 'host')) {
	warn "missing source";
	return undef;
    } else {
	$self->{_source} = $args{source};
    }

    unless (defined $args{type} && is_valid_type($args{type})) {
	warn "missing or invalid type";
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
		warn "invalid ipv4 address";
		return undef;
	    } else {
		$self->{"_$addr"} = $args{$addr};
	    }
	} 
    } elsif ($self->{_proto} eq 'IPv6') {
	for my $addr (qw/ local_address remote_address / ) {
	    unless (is_ipv6 ($args{$addr})) {
		warn "invalid ipv6 address";
		return undef;
	    } else {
		$self->{"_$addr"} = $args{$addr};
	    }
	}
	for my $addr (qw/ local_endpoint remote_endpoint / ) {
	    unless (is_ipv4 ($args{$addr})) {
		warn "invalid ipv4 address";
		return undef;
	    } else {
		$self->{"_$addr"} = $args{$addr};
	    }
	}
    }
    if ($self->{_source} eq 'host') {
	if (defined $args{interface}) {
	    $self->{_interface} = $args{interface};
	} else {
	    warn "missing interface for host tunnel";
	}
    }
	    
    # rebless if we have a specific OS to target 
    # for this tunnel endpoint.

    $args{local_os} eq 'bsd' and 
	bless $self, 'Funknet::Config::Tunnel::BSD';
    $args{local_os} eq 'ios' and 
	bless $self, 'Funknet::Config::Tunnel::IOS';
    $args{local_os} eq 'linux' and
	bless $self, 'Funknet::Config::Tunnel::Linux';
    $args{local_os} eq 'solaris' and
	bless $self, 'Funknet::Config::Tunnel::Solaris';

    return $self;
}

sub as_string {
    my ($self) = @_;
    
    return 
	"$self->{_type}:\n" .
	"$self->{_local_endpoint} -> $self->{_remote_endpoint}\n" . 
	"$self->{_local_address} -> $self->{_remote_address}\n";
}

sub as_hashkey {
    my ($self) = @_;
    
    return 
	"$self->{_type}-" .
	"$self->{_local_endpoint}-$self->{_remote_endpoint}-" . 
	"$self->{_local_address}-$self->{_remote_address}";
}

sub new_from_ifconfig {
    my ($class, $if, $local_os) = @_;
    
    if ($local_os eq 'bsd') {
	return Funknet::Config::Tunnel::BSD->new_from_ifconfig( $if );
    }
    if ($local_os eq 'linux') {
	return Funknet::Config::Tunnel::Linux->new_from_ifconfig( $if );
    }
    if ($local_os eq 'solaris') {
	return Funknet::Config::Tunnel::Solaris->new_from_ifconfig( $if );
    }
    return undef;
}

sub interface {
    my ($self) = @_;
    return $self->{_interface};
}

1;
