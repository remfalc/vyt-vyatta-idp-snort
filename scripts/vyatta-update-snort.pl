#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use VyattaSnortConfig;

my $FILE_SNORT_CONF = '/etc/snort/snort.conf';

my $error_prefix = 'IPS configuration error';

my $config = new VyattaSnortConfig;
my $oconfig = new VyattaSnortConfig;
$config->setup();
$oconfig->setupOrig();

if (!($config->isDifferentFrom($oconfig))) {
  # config not changed. do nothing.
  exit 0;
}

my $err = $config->setupIptables();
if (defined($err)) {
  print "$error_prefix: $err.\n";
  exit 1;
}

if ($config->isEmpty()) {
  # shutdown
  print 'Stopping IPS...';
  my $err = $oconfig->shutdownSnort();
  if (defined($err)) {
    print "$error_prefix: $err.\n";
    exit 1;
  }
  print " Done.\n";
  exit 0;
}

my ($snort_conf) = (undef);
while (1) {
  ($snort_conf, $err) = $config->get_snort_conf();
  last if (defined($err));
  
  $err = $config->checkQueue();
  last if (defined($err));
  
  # remove everything between markers
  $err = $config->removeCfg($FILE_SNORT_CONF);
  last if (defined($err));
  
  # insert new lines between markers
  $err = $config->writeCfg($FILE_SNORT_CONF, $snort_conf);
  last if (defined($err));
 
  # stop snort
  print 'Stopping IPS...';
  $err = $oconfig->shutdownSnort();
  last if (defined($err));
  print " Done.\n";
  
  # start snort
  print 'Starting IPS...';
  $err = $config->startSnort();
  last;
}
if (defined($err)) {
  print "$error_prefix: $err.\n";
  exit 1;
}

print " Done.\n";
exit 0;

