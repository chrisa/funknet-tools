#!/usr/local/bin/perl -w
#
# $Id$
#
# Copyright (c) 2003
#	The funknet.org Group.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#	This product includes software developed by The funknet.org
#	Group and its contributors.
# 4. Neither the name of the Group nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE GROUP AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE GROUP OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

use strict;
use Test::More tests => 18;
use Data::Dumper;

BEGIN { 
    use_ok ( 'Funknet::Config::SystemFileSet' );
    use_ok ( 'Funknet::Config::SystemFile' );
}

# TEST PHASE ONE - open a file, replace its contents, get a diff, write out.

# reset test file
`echo 'foo' > etc/testsysfile.txt`;

my $file = Funknet::Config::SystemFile->new( path => 'etc/testsysfile.txt' );

is (defined $file, 1, 'F::C::SystemFile object created');
is ($file->path, 'etc/testsysfile.txt', '->path OK');
is ($file->old_text, "foo\n", 'old contents OK');

$file->new_text("bar\n");

is ($file->new_text, "bar\n", 'new contents OK');

my $diff = $file->diff;

is ($diff, "@@ -1 +1 @@
-foo
+bar
", 'diff');

$file->write;

my $new_contents = `cat etc/testsysfile.txt`;
is ($new_contents, "bar\n", 'new file written');


# TEST PHASE TWO - repeat above for two files in a set

# reset test files
`echo 'fred' > etc/testsysfile1.txt`;
`echo 'barney' > etc/testsysfile2.txt`;

# create two SystemFile objects
my $file1 = Funknet::Config::SystemFile->new( path => 'etc/testsysfile1.txt' );
my $file2 = Funknet::Config::SystemFile->new( path => 'etc/testsysfile2.txt' );

is (defined $file1, 1, 'F::C::SystemFile object 1 created');
is ($file1->path, 'etc/testsysfile1.txt', '->path OK');
is ($file1->old_text, "fred\n", 'old contents OK');

is (defined $file2, 1, 'F::C::SystemFile object 2 created');
is ($file2->path, 'etc/testsysfile2.txt', '->path OK');
is ($file2->old_text, "barney\n", 'old contents OK');

# create a SystemFileSet to contain them
my $set = Funknet::Config::SystemFileSet->new( files => [ $file1, $file2 ] );

is (defined $set, 1, 'F::C::SystemFileSet created OK');

$file1->new_text("fred1\n");
$file2->new_text("barney1\n");
is ($file1->new_text, "fred1\n", 'new contents OK');
is ($file2->new_text, "barney1\n", 'new contents OK');

my $setdiff = $set->diff;
is ($setdiff, "================================================================================
etc/testsysfile1.txt:
@@ -1 +1 @@
-fred
+fred1
================================================================================

================================================================================
etc/testsysfile2.txt:
@@ -1 +1 @@
-barney
+barney1
================================================================================

", 'set diff OK');

