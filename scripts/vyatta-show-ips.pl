#!/usr/bin/perl

# Author: An-Cheng Huang <ancheng@vyatta.com>
# Date: 2008
# Description: Perl script for IPS show command

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
# Portions created by Vyatta are Copyright (C) 2006, 2007, 2008 Vyatta, Inc.
# All Rights Reserved.
# **** End License ****

use strict;
use lib '/opt/vyatta/share/perl5';
use VyattaSnortUnifiedLog;
use Sort::Versions;

my $SNORT_LOG_DIR = '/var/log/snort';
my $SNORT_LOG_PFX = 'snort-unified.alert';

sub show_file {
  my $file = shift;
  my ($err, $fd) = open_log_file($file);
  die "$err" if (defined($err));

  my ($date, $time, $sgen, $sid, $srev, $class, $prio,
      $sip, $dip, $sp, $dp, $proto);
  while (1) {
    ($err, $date, $time, $sgen, $sid, $srev, $class, $prio,
     $sip, $dip, $sp, $dp, $proto) = get_next_log_entry($fd);
    die "$err" if (defined($err));
    last if (!defined($date));

    print_log_entry($date, $time, $sgen, $sid, $srev, $class, $prio,
                    $sip, $dip, $sp, $dp, $proto);
  }
}

my $logdir = undef;
opendir($logdir, $SNORT_LOG_DIR) or die "Can't open $SNORT_LOG_DIR: $!";
my @logfiles = sort versioncmp (grep(/^$SNORT_LOG_PFX/, readdir($logdir)));
closedir $logdir;
if (scalar(@logfiles) <= 0) {
  print "No log files found\n";
  exit 0;
}
foreach (@logfiles) {
  show_file("$SNORT_LOG_DIR/$_");
}

