package Funknet::Config::AccessList;
use strict;

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
					           local_router => 'ios',
					           local_host  => '213.210.34.174',
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
    $args{source_addr} =~ /^\d+\.\d+\.\d+\.\d+$/ or return undef;
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
	my $cli = Funknet::Config::CLI->new( local_as => $args{source_as},
					     local_host => $args{local_host},
					     local_router => $args{local_router}, 
					   );
	my $self = $cli->get_access_list( remote_addr => $args{peer_addr},
					  dir => $args{dir} );
	if (defined $self) {
	    return bless $self, $class;
	} else {
	    return undef;
	}
    }
    return undef;
}

sub _get_whois {
    my (%args) = @_;

    my $rtconfig = 
	'/home/chris/bin/RtConfig -h whois.funknet.org -p 43 -s FUNKNET -protocol ripe ' . 
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
	return $acl;
    } else {
	return undef;
    }
}

sub name {
    my ($self) = @_;
    return $self->{_name};
}

sub config {
    my ($self) = @_;
    my $config = $self->{_acl_text}."!\n";
    $config .= "route-map $self->{_name} permit 1\n" . 
	       " match ip address prefix-list $self->{_name}\n!\n";
}

sub diff {
    my ($whois, $host) = @_;
    return "acl diff here";
}

1;
