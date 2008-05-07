#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use VyattaSnortConfig;
use File::Copy;

# use the proper snort config file and stop/start snort depending on config
# arguments: <antivirus_status> <ips_status> [orig_only]

my $FILE_SNORT_CONF = '/etc/snort/snort.conf';
my $FILE_IPS_CONF = '/etc/snort/ips.conf';
my $FILE_ANTIVIRUS_CONF = '/etc/snort/antivirus.conf';

my ($ret_antiv, $ret_ips, $orig_only) = @ARGV;

my $error_prefix = 'Content Inspection configuration error';

my $config = new VyattaSnortConfig;
my $oconfig = new VyattaSnortConfig;
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
exit 0;

