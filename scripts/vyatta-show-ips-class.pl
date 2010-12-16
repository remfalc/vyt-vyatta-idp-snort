#!/usr/bin/perl
#
# Module: vyatta-show-ips-class.pl
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
# Date: December 2010
# Description: show snort rule classifications summary
# 
# **** End License ****
#

use strict;
use warnings;
use Getopt::Long;

my $class_file  = undef;
my $rule_dir    = undef;
my $preproc_dir = undef;
GetOptions('classfile=s'  => \$class_file,
           'ruledir=s'    => \$rule_dir,
           'preprocdir=s' => \$preproc_dir,
          );

die "Must set --classfile"  if ! defined($class_file);
die "Must set --ruledir"    if ! defined($rule_dir);
die "Must set --preprocdir" if ! defined($preproc_dir);
if (! -e $class_file) {
    print "No classification file found\n";
    exit 1;
}
open(my $CLASS, '<', $class_file) or die "Cannot open $class_file: $!";

my %prio_hash  = ();
my %class_hash = ();
my %classname_hash =();
while (<$CLASS>) {
    next if (!/^\s*config\s+classification:\s+(.*)$/);
    my ($name, $desc, $prio) = split /,/, $1;
    $prio =~ s/\s*(\d+)\s*/$1/;
    $prio_hash{$prio}{$name} = $desc;
    $classname_hash{$name} = $prio;
}
close $CLASS;

sub parse_rules {
    my ($dir) = @_;

    opendir(my $DIR, "$dir") or die "Cannot open $dir: $!";
    my @rule_files = grep /\.rules$/, readdir($DIR);
    closedir $DIR;

    foreach my $file (@rule_files) {
        open(my $RIN, '<', "$dir/$file") or 
            die "Cannot open $dir/$file: $!";
        while (<$RIN>) {
            my $line = $_;
            if (/[(; ]classtype:\s*([^;]+);/) {
                my $class = $1;
                if ($line =~ /^#/) {
                    $class_hash{'disabled'}{$class}++;
                } else {
                    $class_hash{'enabled'}{$class}++;
                }
                my $prio =$classname_hash{$class};
                if (defined $prio) {
                    if ($line =~ /^#/) {
                        $class_hash{$prio}{'disabled'}++;
                    } else {
                        $class_hash{$prio}{'enabled'}++;
                    }
                } else {
                    print "No prio found [$line]\n";
                }
            }
        }
        close $RIN;
    }
}

if (! -d $rule_dir) {
    print "No snort rule directory found\n";
    exit 1;
}
parse_rules($rule_dir);
parse_rules($preproc_dir) if -d $preproc_dir;

my $format = "%-60s %8s %8s\n";
printf("\n$format\n", 'Snort Classifications', 'Enabled', 'Disabled');

my %grand_tot = ();
foreach my $num (1..4) {
    printf("\n$format", "Priority $num", '', '');
    printf($format, '=' x 10, '', '');
    while (my ($key, $value) = each(%{$prio_hash{$num}})){
        my ($enabled, $disabled) = (undef, undef);
        $enabled  = $class_hash{'enabled'}{$key};
        $enabled  = 0 if ! defined $enabled;
        $disabled = $class_hash{'disabled'}{$key};
        $disabled = 0 if ! defined $disabled;
        printf($format, $value, $enabled, $disabled);
    }
    my ($tot_enable, $tot_disable) = (undef, undef);
    printf($format, '', '-' x 8, '-' x 8);
    $tot_enable  = $class_hash{$num}{'enabled'};
    $tot_enable  = 0 if ! defined $tot_enable;
    $tot_disable = $class_hash{$num}{'disabled'};
    $tot_disable = 0 if ! defined $tot_disable;
    printf($format, '', $tot_enable, $tot_disable);
    $grand_tot{'enabled'}  += $tot_enable;
    $grand_tot{'disabled'} += $tot_disable;
}
printf("\n\n$format", 'Total', '=' x 8, '=' x 8);
printf($format, '', $grand_tot{'enabled'}, $grand_tot{'disabled'});

# end of file
