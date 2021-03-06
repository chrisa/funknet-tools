use 5.006001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	      NAME              => 'funknet-tools',
	      VERSION_FROM      => 'lib/Funknet/Config.pm', # finds $VERSION
	      PREREQ_PM         => {
				    Net::IPv4Addr => ,
				    Net::Telnet => ,
				   },
	      EXE_FILES         => [
				    'bin/funknet-config',
				    'bin/dynamic-update',
				    'bin/whois-update',
				    'bin/whois-server',
				   ],
	      INSTALLSCRIPT     => '/usr/bin',
	      ($] >= 5.005 ?     
	       (AUTHOR         => 'chris <chris@nodnol.org>') : ()),
	     );
