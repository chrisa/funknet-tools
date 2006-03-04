#!/usr/bin/perl
use strict;
use Test::More;

# 1: without timestamps

if (-f 'whois-server-FUNKNET.pid') {
    system("kill `cat whois-server-FUNKNET.pid` 2> /dev/null");
}

# start a whoisd on localhost
my $server_pid;
unless ($server_pid = fork()) {
    exec("/usr/bin/perl -Ilib bin/whois-server -f t/updater-tests/funknet_whois.conf > /dev/null 2>&1");
}

my $testfile = 't/updater-tests/test-update.txt.asc';
my $tests = 100;

open TESTFILE, $testfile
     or die "can't open testfile $testfile: $!";

my $filetext;
{
     local $/ = undef;
     $filetext = <TESTFILE>;
}
close TESTFILE;

plan tests => $tests;

for (my $i = 0; $i <= $tests; $i++) {
    open UPDATER, "|/usr/bin/perl -Ilib bin/whois-update -f t/updater-tests/funknet_whois.conf > test-update.log"
      or die "couldn't start whois-update: $!";
    
    print UPDATER $filetext;
    my $result = close UPDATER;
    ok($result, "update $i ok");
}

kill 9, $server_pid, $server_pid + 1; # try to get the shell and the child perl process. 
