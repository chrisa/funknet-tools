package Funknet::Config::Validate;
use strict;
use base qw/ Exporter /;
use vars qw/ @EXPORT_OK /;

@EXPORT_OK = qw/ is_ipv4 is_ipv6 is_valid_type is_valid_as is_valid_os is_valid_router /;

sub is_ipv4 {
    my ($addr) = @_;
    return 1;
}

sub is_ipv6 {
    my ($addr) = @_;
    return 1;
}

sub is_valid_type {
    my ($type) = @_;

    if ($type eq 'sit'  ||
	$type eq 'ipip' ||
	$type eq 'gre') {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_os {
    my ($os) = @_;

    if ($os eq 'linux'   ||
	$os eq 'bsd'     ||
	$os eq 'ios'     ||
	$os eq 'solaris' ) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_router {
    my ($router) = @_;

    if ($router eq 'zebra' ||
	$router eq 'ios'   ) {
	return 1;
    } else {
	return 0;
    }
}

sub is_valid_as {
    my ($as) = @_;
    
    if ($as =~ /^AS\d+/) {
	return 1;
    } else {
	return 0;
    }
}

1;
