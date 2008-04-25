#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use VyattaSnortConfig;

# writes the ips config file and exits with proper status:
#   0: success, something changed
#   1: not configured
#   2: failed (error message already displayed)
#   3: success, nothing changed

my $FILE_SNORT_CONF = '/etc/snort/ips.conf';

my $error_prefix = 'IPS configuration error';

my $config = new VyattaSnortConfig;
my $oconfig = new VyattaSnortConfig;
$config->setup();
$oconfig->setupOrig();

if ($config->isEmpty()) {
  # not configured
  exit 1;
}

if (!($config->isDifferentFrom($oconfig))) {
  # config not changed. do nothing.
  exit 3;
}

my ($snort_conf, $err) = (undef, undef);
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
  last;
}

if (defined($err)) {
  # failed
  print "$error_prefix: $err.\n";
  exit 2;
}

exit 0;

