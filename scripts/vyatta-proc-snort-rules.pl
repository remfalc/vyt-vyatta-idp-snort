#!/usr/bin/perl
#
# Module: vyatta-proc-snort-rules.pl
# 
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2008-2010 Vyatta, Inc.
# All Rights Reserved.
# 
# Author: An-Cheng Huang
# Date: April 2008
# Description: process snort rules
# 
# **** End License ****
#

use strict;
use Getopt::Long;

sub usage {
  print <<EOF;
Arguments:
  --classfile <file>    Location of the classification file
  --ruledir <dir>       Directory containing the rules
  --outdir <dir>        Directory for outputing the rules
EOF
}

my $class_file = undef;
my $rule_dir = undef;
my $out_dir = undef;
GetOptions('classfile=s' => \$class_file,
           'ruledir=s' => \$rule_dir,
           'outdir=s' => \$out_dir);
if (!defined($class_file) || !defined($rule_dir) || !defined($out_dir)) {
  usage();
  exit 1;
}

my %class_hash = ();
my %prio_hash = ( '1' => 'p1action',
                  '2' => 'p2action',
                  '3' => 'p3action',
                  '4' => 'p4action',
                  'default' => 'p4action' );

open(my $CLASS, "<", $class_file) or die "Cannot open $class_file: $!";
while (<$CLASS>) {
  next if (!/^\s*config\s+classification:\s+(.*)$/);
  my ($name, $desc, $prio) = split /,/, $1;
  $prio =~ s/\s*(\d+)\s*/$1/;
  $class_hash{$name} = $prio;
}
close $CLASS;

opendir(RIN_DIR, "$rule_dir") or die "Cannot open $rule_dir: $!";
my @rule_files = grep /\.rules$/, readdir(RIN_DIR);
closedir RIN_DIR;

if (! -d $out_dir) {
  mkdir($out_dir) or die "Cannot create $out_dir: $!";
}

foreach my $file (@rule_files) {
  open(my $RIN, "<", $rule_dir/$file) or die "Cannot open $rule_dir/$file: $!";
  open(my $ROUT, ">", $out_dir/$file) or die "Cannot open $out_dir/$file: $!";
  while (<$RIN>) {
    if (!/^alert\s/ and !/^# alert\s/ and !/^pass\s/) {
      print ${ROUT};
      next;
    }
    my $prio = undef;
    if (/[(; ]classtype:\s*([^;]+);/) {
      $prio = $class_hash{$1};
    }
    if (/[(; ]priority:\s*([^;]+);/) {
      $prio = $1;
    }
    if (!defined($prio)) {
      print ${ROUT};
      next;
    }
    if (!defined($prio_hash{$prio})) {
      print "prio [$prio] not defined\n";
    }
    my $action = (defined($prio_hash{$prio}))
                    ? $prio_hash{$prio} : $prio_hash{'default'};
    if (/^#/) {
        s/^# alert\s/# $action /;
    } else {
        s/^alert\s/$action /;
        s/^pass\s/p4action /;
    }
    print ${ROUT};
  }
  close $RIN;
  close $ROUT;
}

