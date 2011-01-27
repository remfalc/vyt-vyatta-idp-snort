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
# Portions created by Vyatta are Copyright (C) 2006-2011 Vyatta, Inc.
# All Rights Reserved.
# **** End License ****

use strict;
use lib '/opt/vyatta/share/perl5';
use Vyatta::Snort::UnifiedLog;
use Sort::Versions;
use Vyatta::Config;

my $SNORT_LOG_DIR = '/var/log/snort';
my $SNORT_LOG_PFX = 'snort-unified.alert';

my $summary = (defined($ARGV[0]) && $ARGV[0] eq 'summary') ? 1 : 0;

my %prio_hash = ();
my %class_hash = ();
my %sid_hash = ();
my %date_hash = ();

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

    # update stats
    $prio_hash{$prio} = (defined($prio_hash{$prio}))
                        ? ($prio_hash{$prio} + 1) : 1;
    $class_hash{$class} = (defined($class_hash{$class}))
                          ? ($class_hash{$class} + 1) : 1;
    my $sid_str = "$sgen:$sid:$srev";
    $sid_hash{$sid_str} = (defined($sid_hash{$sid_str}))
                          ? ($sid_hash{$sid_str} + 1) : 1;
    $date_hash{$date} = (defined($date_hash{$date}))
                        ? ($date_hash{$date} + 1) : 1;

    print_log_entry($date, $time, $sgen, $sid, $srev, $class, $prio,
                    $sip, $dip, $sp, $dp, $proto) if (!$summary);
  }
}

sub show_summary {
  my @prios = sort versioncmp (keys %prio_hash);
  my @classes = sort versioncmp (keys %class_hash);
  my @sids = sort versioncmp (keys %sid_hash);
  my @dates = sort versioncmp (keys %date_hash);

  # total
  my $total = 0;
  map { $total += $prio_hash{$_} } @prios;
  print "  Total number of events: $total\n";

  print "\n  Breakdown by priorities:\n";
  foreach (@prios) {
    print "    Priority $_: $prio_hash{$_}\n";
  }
  
  print "\n  Breakdown by classes:\n";
  foreach (@classes) {
    my ($name, $desc) = get_class_strs($_);
    print "    $name: $class_hash{$_} ($desc)\n";
  }
  
  print "\n  Breakdown by signatures:\n";
  foreach (@sids) {
    my $desc = get_sig_msg($_);
    print "    [$_]: $sid_hash{$_} ($desc)\n";
  }

  print "\n  Breakdown by dates:\n";
  foreach (@dates) {
    print "    $_: $date_hash{$_}\n";
  }
}

my $logdir = undef;
opendir($logdir, $SNORT_LOG_DIR) or die "Can't open $SNORT_LOG_DIR: $!";
my @logfiles = sort versioncmp (grep(/^$SNORT_LOG_PFX/, readdir($logdir)));
closedir $logdir;
if (scalar(@logfiles) <= 0) {
  my $config = new Vyatta::Config;
  $config->setLevel('content-inspection ips log');
  if (! $config->existsOrig('local')) {
      print "Local logging not enabled\n";
  } else {
    print "No log files found\n";
  }
  exit 0;
}

# display the starting time
$logfiles[0] =~ m/$SNORT_LOG_PFX\.(\d+)/;
my $tstr = (($summary) ? 'Summary of ' : '') . 'IPS events logged since '
           . localtime($1);
my $div = ('=' x length($tstr));

$| = 1;
if (!$summary) {
  print "$div\n$tstr\n$div\n";
} else {
  print "Processing log files...\n";
}

foreach (@logfiles) {
  show_file("$SNORT_LOG_DIR/$_");
}

if ($summary) {
  print "Done.\n\n$div\n$tstr\n$div\n";
  show_summary();
}

