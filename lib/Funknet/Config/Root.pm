package Funknet::Config::Root;
use strict;

=head1 NAME

Funknet::Config::Root

=head1 DESCRIPTION

Class abstracting methods of getting root. 

=head1 METHODS

=head2 new

=head2 exec_root

=cut

sub new {
    my ($class) = @_;
    my $self = bless {}, $class;

    my $root_method = Funknet::Config::ConfigFile->root;

    if ($root_method eq 'sudo') {
	
	$self->{_exec} = 
	    sub ($) {
		my ($cmd) = @_;
		system "sudo $cmd";
	    };

    } elsif ($root_method eq 'userv') {

	$self->{_exec} = 
	    sub ($) {
		my ($cmd) = @_;
		system "userv $cmd"; # XXX this isn't right
	    };

    } elsif ($root_method eq 'runas') {

	$self->{_exec} = 
	    sub ($) {
		my ($cmd) = @_;
		system "$cmd";
	    };

    } else {
	return undef;
    }
}

sub exec_root {
    my ($self, $cmdset) = @_;

    for my $cmd ($cmdset->cmds) {
	&{ $self->{_exec} }($cmd);
    }
}

1;
