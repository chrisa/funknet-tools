package Funknet::Config::AccessList;
use strict;

sub new {
    my ($class, %args) = @_;

    $args{source_as} =~ /^\d+$/ or return undef;
    $args{peer_as}   =~ /^\d+$/ or return undef;
    $args{source_addr} =~ /^\d+\.\d+\.\d+\.\d+$/ or return undef;
    $args{peer_addr}   =~ /^\d+\.\d+\.\d+\.\d+$/ or return undef;
    $args{dir}      =~ /^(import|export)$/ or return undef;
    
    if ($args{source} eq 'whois') {
	my $self = bless {}, $class;
	$self->_get_whois(%args);
	return $self;
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
    my ($self, %args) = @_;

    my $rtconfig = 
	'/usr/local/bin/RtConfig -h whois.funknet.org -p 43 -s FUNKNET -protocol ripe ' . 
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
    
    if (length $acl_text) {
	$self->{_acl_text} = $acl_text;
	$self->{_name} = $acl_name;
	return $self;
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

1;
