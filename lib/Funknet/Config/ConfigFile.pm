package Funknet::Config::ConfigFile;
use strict;
use Data::Dumper;
use vars qw/ $AUTOLOAD /;

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
#	$self->{config}->{$key} = [ split /,/,$values ];
	$self->{config}->{$key} = $values;
    }

    close CONF;
    return $self;
}

sub AUTOLOAD {
    my ($self) = @_;
    my $key = $AUTOLOAD;
    $key =~ s/Funknet::Config::ConfigFile:://;
    if (exists $self->{config}->{$key}) { 
	return $self->{config}->{$key};
    } else {
	warn "accessing non existent config param $key";
	return undef;
    }
}

sub DESTROY {};

1;
