#!/usr/bin/perl
#
# Module: vyatta-update-inspection.pl
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
# Description: update content inspection
# 
# **** End License ****
#
use strict;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Snort::Config;
use Vyatta::Config;
use File::Copy;

# use the proper snort config file and stop/start snort depending on config
# arguments: <antivirus_status> <ips_status> [orig_only]

my $FILE_SNORT_CONF = '/etc/snort/snort.conf';
my $FILE_IPS_CONF = '/etc/snort/ips.conf';
my $FILE_ANTIVIRUS_CONF = '/etc/snort/antivirus.conf';

my ($ret_antiv, $ret_ips, $orig_only) = @ARGV;
my ($inspect_active, $global_inspect, $interface_dirs_ref, $zone_pairs_ref);

my $error_prefix = 'Content Inspection configuration error';
my $vconfig = new Vyatta::Config;
my $config = new Vyatta::Snort::Config;
my $oconfig = new Vyatta::Snort::Config;
if (defined($orig_only)) {
  $config->setupOrig();
} else {
  $config->setup();
}
$oconfig->setupOrig();

if ($ret_antiv eq '2' || $ret_ips eq '2') {
  # error. abort.
  exit 1;
}

if ($ret_antiv eq '1' && $ret_ips eq '1') {
  # neither is configured. shutdown
  ($inspect_active, $global_inspect, $interface_dirs_ref, $zone_pairs_ref) =
      $config->inspect_enabled_list('all-directions','v4', 'proposed-config');

  if ($inspect_active eq 'true') {
    print "Error: IPv4 Content-inspection enabled " .
          "on an interface or a zone. Cannot delete it\n";
    exit 1;
  }

  exit 0 if (!$vconfig->existsOrig('content-inspection ips'));
  print 'Stopping Content Inspection...';
  my $err = $oconfig->shutdownSnort();
  if (defined($err)) {
    print "$error_prefix: $err.\n";
    exit 1;
  }
  print " Done.\n";
  exit 0;
}

if ($ret_antiv eq '3' && $ret_ips eq '3') {
  # neither changed. (should not happen)
  exit 0;
}

# at least one is configured
my $err = undef;
while (1) {
  # use the right config file
  my $src = undef;
  if ($ret_ips eq '1') {
    # ips is not configured. use the antivirus config.
    $src = $FILE_ANTIVIRUS_CONF;
  } else {
    # ips is configured. use the ips config.
    # (antivirus is covered either way.)
    ($inspect_active, $global_inspect, $interface_dirs_ref, $zone_pairs_ref) =
	$config->inspect_enabled_list('all-directions','v4','proposed-config');

    my @interface_dirs = @$interface_dirs_ref;
    my @zone_pairs = @$zone_pairs_ref;
    if ($global_inspect eq 'true' &&
        (scalar(@interface_dirs) != 0 || scalar(@zone_pairs) != 0)) {
        print "Error: IPv4 Content-inspection enabled on an interface or a " .
              "zone. Cannot enable inspect-all\n";
        exit 1;
    }
    $src = $FILE_IPS_CONF;
  }
  if (!copy($src, $FILE_SNORT_CONF)) {
    $err = "Copy failed: $!";
    last;
  }

  # set up iptables chains
  $err = $config->setupIptables();
  last if (defined($err));

  # stop snort
  print 'Stopping Content Inspection...';
  $err = $oconfig->shutdownSnort();
  last if (defined($err));
  print " Done.\n";
  
  # start snort
  print 'Starting Content Inspection...';
  $err = $config->startSnort();
  last;
}
if (defined($err)) {
  print "$error_prefix: $err.\n";
  exit 1;
}

print " Done.\n";

if ($inspect_active eq 'false') {
  print "Warning: IPv4 Content-inspection not enabled " .
        "globally or on any interface or zone\n";
}

# Need to do the same checks as above using
# inspect_enabled_list() for IPv6 in future

exit 0;

