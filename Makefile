test:
	perl -Ilib -MTest::Harness -e 'runtests(@ARGV);' t/*.t