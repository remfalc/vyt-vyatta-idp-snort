#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use VyattaSnortConfig;

my $FILE_SNORT_CONF = '/etc/snort/snort.conf';
my $SNORT_INIT = '/etc/init.d/snort';
my $SNORT_DONE = '/var/run/snort_inline_init.pid';

my $error_prefix = 'Snort IDP configuration error';

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

sub shutdownSnort {
  # remove iptables queue rule(s) and stop snort (must be in this order)
  print 'Stopping Snort IDP...';
  my $err = $oconfig->removeQueue();
  if (!defined($err)) {
    system("$SNORT_INIT stop >&/dev/null");
    if ($? >> 8) {
      $err = 'Cannot stop Snort IDP';
    }
  }
  if (defined($err)) {
    print "\n$error_prefix: $err.\n";
    exit 1;
  }
  print " Done.\n";
}

if ($config->isEmpty()) {
  # shutdown
  shutdownSnort();
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
  shutdownSnort();
  
  # start snort
  print 'Starting Snort IDP...';
  system("$SNORT_INIT start >&/dev/null");
  if ($? >> 8) {
    $err = 'Cannot start Snort IDP';
    last;
  }
  # wait for snort to finish initialization before adding queue rules
  # to avoid blocking traffic
  my $count = 0;
  $| = 1;
  while ($count < 30 && (! -f $SNORT_DONE)) {
    print '.';
    sleep 2;
    $count++;
  }
  if ($count == 30) {
    $err = 'Snort IDP initialization failed';
    last;
  }
 
  # add iptables queue rule(s)
  $err = $config->addQueue();
  last;
}
if (defined($err)) {
  print "$error_prefix: $err.\n";
  exit 1;
}

print " Done.\n";
exit 0;

