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

my @testfiles = `ls t/updater-tests/*.asc`;
plan tests => scalar @testfiles;

for my $file (@testfiles) {
    chomp $file;

    open TESTFILE, $file
      or die "can't open testfile $file: $!";

    my $filetext;
    {
        local $/ = undef;
        $filetext = <TESTFILE>;
    }
    close TESTFILE;
    

    open UPDATER, "|/usr/bin/perl -Ilib bin/whois-update -t -f t/updater-tests/funknet_whois.conf > /dev/null 2>&1"
      or die "couldn't start whois-update: $!";
    
    print UPDATER $filetext;
    my $result = close UPDATER;
    ok($result, $file);
}

kill 9, $server_pid, $server_pid + 1; # try to get the shell and the child perl process. 
