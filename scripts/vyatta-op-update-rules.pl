#!/usr/bin/perl
#
# Module: vyatta-op-update-rules.pl
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
# Portions created by Vyatta are Copyright (C) 2010 Vyatta, Inc.
# All Rights Reserved.
# 
# Author: Stig Thormodsrud
# Date: May 2010
# Description: script to interactively update snort rules
# 
# **** End License ****
#

use strict;
use lib "/opt/vyatta/share/perl5";

use Vyatta::Config;

my $sbin = '/opt/vyatta/sbin';
my $config = new Vyatta::Config;
my $path = 'content-inspection ips auto-update';

if (! $config->existsOrig($path)) {
    print "IPS auto-update is not configured.\n";
    exit 1;
}

my ($cmd, $rc, $file);

if ($config->existsOrig("$path oink-code")) {
    print "Requesting download from snort.org\n";
    $file = 'snortrules-snapshot-2853.tar.gz';
    $cmd = "$sbin/vyatta-get-snort-rules.pl $file 1";
} elsif ($config->existsOrig("$path snortvrt-subscription")) {
    $file = 'snortrules-snapshot-2853.tar.gz';
    $cmd = "$sbin/vg_snort_update";
} else {
    print "Error: unexepted update type\n";
    exit 1;
}

$rc = system($cmd);
if ($rc) {
    exit 1;
}

$cmd = "$sbin/vyatta-proc-snort-updates /tmp/$file >/dev/null 2>&1 &";
system($cmd);


print "\nStarting unpack & processing of new rules.\n\n";
print "Note: this process will run in the background and will\n";
print "take some time.  You can use 'show ips update-log'\n";
print "to view progress/results.\n\n";

exit 0;
