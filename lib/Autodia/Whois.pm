package Autodia::Handler::Whois;

require Exporter;

use strict;
use Data::Dumper;

use Net::Whois::RIPE;

use vars qw($VERSION @ISA @EXPORT);
use Autodia::Handler;

@ISA = qw(Autodia::Handler Exporter);

use Autodia::Diagram;


sub _parse {
    my $self     = shift;
    my $fh       = shift;
    my $filename = shift;
    my $Diagram  = $self->{Diagram};
    
    my $Class;
    
    my $w = Net::Whois::RIPE->new( 'whois.funknet.org' );
    
    foreach my $line (<$fh>) {
	chomp $line;
	
	# let's assume it's an aut-num for now. 
	$w->type('aut-num');
	my $aut_num = $w->query($line);
	
	$Class = Autodia::Diagram::Class->new($aut_num->as_name);

	$Class->add_attribute({ name => $aut_num->admin_c });
	$Class->add_attribute({ name => $aut_num->tech_c });
	$Class->add_attribute({ name => $aut_num->mnt_by });
	
	$Diagram->add_class($Class);
	
	for my $tun( $aut_num->tun ) {
	    
	    my $Component = Autodia::Diagram::Component->new($tun);

#	    $Component->add_attribute({ name => $route->route });
	    
	    my $exists = $Diagram->add_component($Component);
	    if (ref $exists) {
		$Component = $exists;
	    }
	    
	    my $Dependancy = Autodia::Diagram::Dependancy->new($Class, $Component);
	    $Diagram->add_dependancy($Dependancy);
	    $Class->add_dependancy($Dependancy);
	    $Component->add_dependancy($Dependancy);
	}
	
	# get the networks announced out of this AS
	
	$w->type('route');
	$w->inverse_lookup('origin');
	
	my $routes = $w->query_iterator($line);
	while (my $route = $routes->next) {
	    
	    my $Component = Autodia::Diagram::Component->new($route->descr);

#	    $Component->add_attribute({ name => $route->route });
	    
	    my $exists = $Diagram->add_component($Component);
	    if (ref $exists) {
		$Component = $exists;
	    }
	    
	    my $Dependancy = Autodia::Diagram::Dependancy->new($Class, $Component);
	    $Diagram->add_dependancy($Dependancy);
	    $Class->add_dependancy($Dependancy);
	    $Component->add_dependancy($Dependancy);
	    
	}
	
    }

    $self->{Diagram} = $Diagram;
    close $fh;
    return;
}

    
1;
