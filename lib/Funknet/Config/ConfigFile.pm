package Funknet::Config::ConfigFile;
use strict;
use Data::Dumper;
use vars qw/ $AUTOLOAD /;
use Carp qw/ cluck /;
use Funknet::Config::Validate qw / is_ipv4 is_ipv6 is_valid_as is_valid_router is_valid_os /;
use base qw/ Funknet::Config /;

=head1 NAME

Funknet::Config::ConfigFile

=head1 SYNOPSIS

  my $config = Funknet::Config::ConfigFile->new( $configfile )

=head1 DESCRIPTION

  An abstraction over a simple test config file. Syntax is:

    key = value
    key = value, value, value

=head1 METHODS

=head2 new

Call with one arg of the full path to the config file. Returns a
config object which you can use to access keys. 

=head2 AUTOLOAD

To retrieve a key, call ->key on the ConfigFile object, or as a class
method. Multi-value key semantics: called in scalar context, returns
the value, or the first value of a list. Called in list context,
returns either the list or just the on value. Never returns a
reference.

=cut


my $config;

sub new {
    my ($class, $file) = @_;
    my $self = bless {}, $class;
    open CONF, $file
	or die "can't open config file $file: $!";
    while (my $line = <CONF>) {
	chomp $line;
	next unless $line;
	next if $line =~ /^#/;
	my ($key, $values) = $line =~ /(.+)\s*=\s*(.+)/;
	$key =~ s/^\s+//;
	$key =~ s/\s+$//;
	$values =~ s/^\s+//;
	$values =~ s/\s+$//;
	if ($values =~ /,/) {
	    $config->{$key} = [ split /\s*,\s*/,$values ];
	} else {
	    $config->{$key} = $values;
	}
    }
    close CONF;
    $self->{config} = $config;

    unless (defined $config->{local_as} && is_valid_as($config->{local_as})) {
	$self->warn("missing local_as");
	return undef;
    } 
    unless (defined $config->{local_host} && is_ipv4($config->{local_host})) {
	$self->warn("missing local_host");
	return undef;
    } 
    unless (defined $config->{local_endpoint} && is_ipv4($config->{local_endpoint})) {
	$self->warn("missing local_endpoint");
	return undef;
    } 
    unless (defined $config->{local_router} && is_valid_router($config->{local_router})) {
	$self->warn("missing local_router");
	return undef;
    } 
    unless (defined $config->{local_os} && is_valid_os($config->{local_os})) {
	$self->warn("missing local_os");
	return undef;
    } 

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
	$self->warn("accessing non existent config param $key");
	return undef;
    }
}

sub DESTROY {};

1;
