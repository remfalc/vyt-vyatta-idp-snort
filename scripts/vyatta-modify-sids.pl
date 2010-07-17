#!/usr/bin/perl
#
# Module: vyatta-modify-sids.pl
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
# Description: read disable-sids/enable-sids and updates rules
# 
# **** End License ****
#

use Getopt::Long;

use strict;
use warnings;

#
# This script can be called from configuration mode or from the 
# auto-update script.  
#

my $debug = 0;

sub read_file {
    my ($file) = @_;

    my @lines = ();
    if ( -e $file) {
      open(my $FILE, '<', $file) or die "Error: read [$file] $!";
      @lines = <$FILE>;
      close($FILE);
      chomp @lines;
    }
    return @lines;
}

sub write_file {
    my ($file, @lines) = @_;	    

    if (scalar(@lines) > 0) {
      open(my $FILE, '>', $file) or die "Error: write [$file] $!";
      print $FILE join("\n", @lines), "\n";
      close($FILE);
    } else {
      system("rm -f $file");
    }
}

sub add_item {
    my ($file, $sid) = @_;

    my @lines = read_file($file);
    foreach my $line (@lines) {
        return if $line eq $sid;
    }
    push @lines, $sid;
    write_file($file, @lines);
    return @lines; 
}

sub del_item {
    my ($file, $sid) = @_;

    my @lines = read_file($file);
    my @new_lines = ();
    foreach my $line (@lines) {
        push @new_lines, $line if $line ne $sid;
    }
    write_file($file, @new_lines) if scalar(@lines) ne scalar(@new_lines);
    return @new_lines;
}

sub parse_sid {
    my (@lines) = @_;

    my @new_lines = ();

    foreach my $line (@lines) {
        my ($gid, $sid) = (undef, undef);
        if ($line =~ /:/) {
            if ($line =~ /^(\d+):(\d+)$/) {
                $gid = $1;
                $sid = $2;
                $sid = undef if $gid != 1;
            } else {
                die "unexpected error parsing gid:sid";
            }
        } else {
            if ($line =~ /^(\d+)$/) {
                $gid = 1;
                $sid = $1;
            } else {
                die "unexpected error parsing sid";
            }
        }
        push @new_lines, "$gid:$sid" if defined $sid;
    }

    return @new_lines;
}

sub update_rules {
    my ($rule_dir, $disable_file, $enable_file) = @_;

    print "update_rules()\n" if $debug;

    my $count = 0;
    my @lines;
    my %dsids;
    my %esids;
 
   @lines = read_file($disable_file);
    if (scalar(@lines) > 0) {
        @lines = parse_sid(@lines);
        %dsids = map { $_ => 1 } @lines;
        $count += scalar(@lines);
    }
    print "disable count = $count\n" if $debug;

    @lines = read_file($enable_file);
    if (scalar(@lines) > 0) {
        @lines = parse_sid(@lines);
        %esids = map { $_ => 1 } @lines;
        $count += scalar(@lines);
    }
    print "both count = $count\n" if $debug;

    return 0 if $count == 0;

    opendir(my $RIN_DIR, "$rule_dir") or die "Cannot open [$rule_dir]: $!";
    my @rule_files = grep /\.rules$/, readdir($RIN_DIR);
    closedir $RIN_DIR;

    my ($tot, $ok, $disabled, $comments, $err) = (0,0,0,0,0);

    foreach my $file (@rule_files) {
        open(my $RIN, '<', "$rule_dir/$file") or 
            die "Cannot open $rule_dir/$file: $!";
        my $output = '';
        while (<$RIN>) {
            my $line = $_;
            chomp $line;
            $tot++;
            if (/^#?\s*p[1234]action.*sid:(\d+);.*$/) {
                my $sid = "1:$1";
                if (/^#/) {
                    $disabled++;
                    if (defined $dsids{$sid}) {
                        # already disabled
                        $dsids{$sid}++;
                    }
                    if ($esids{$sid}) {
                        print "enable [$sid] [$file]\n" if $debug;
                        $line =~ s/^#\s*(.*)/$1/;
                        $esids{$sid}++;
                    }
                } else {
                    $ok++;
                    if (defined $esids{$sid}) {
                        # already enabled
                        $esids{$sid}++;
                    }
                    if ($dsids{$sid}) {
                        print "disable [$sid] [$file]\n" if $debug;
                        $line = "# $line";
                        $dsids{$sid}++;
                    }
                }
            } else {
                if ($line eq '') {
                    # whitespace
                } elsif ($line =~ /^#/) {
                    $comments++;
                } else {
                    $err++;
                    print "Warning: not found [$line] in [$file]\n";
                }
            }
            $output .= "$line\n";
        }
        close $RIN;
        open(my $ROUT, '>', "$rule_dir/$file") or 
            die "Cannot open $rule_dir/$file: $!";
        print $ROUT $output;
        close $ROUT;
    }

    foreach my $sid (sort keys %dsids) {  
        print "checking dsids [$sid]\n" if $debug;
        if ($dsids{$sid} == 1) {
            print "Warning: disable-sid [$sid] not found.\n";
        }
    }

    foreach my $sid (sort keys %esids) {  
        print "checking esids [$sid]\n" if $debug;
        if ($esids{$sid} == 1) {
            print "Warning: enable-sid [$sid] not found.\n";
        }
    }
    
    if ($debug) {
        print "\n";
        print "Total line: [$tot]\n";
        print "        ok: [$ok]\n";
        print "  comments: [$comments]\n";
        print "  disabled: [$disabled]\n";
        print "     error: [$err]\n\n";
    }

    return 0;
}

sub parse_gid_sid {
    my (@lines) = @_;

    my @new_lines = ();

    foreach my $line (@lines) {
        my ($gid, $sid) = (undef, undef);
        if ($line =~ /:/) {
            if ($line =~ /^(\d+):(\d+)$/) {
                $gid = $1;
                $sid = $2;
            } else {
                die "unexpected error parsing gid:sid";
            }
            push @new_lines, "$line" if defined $gid and $gid != 1;
        } 
    }

    return @new_lines;
}

sub update_preproc_rules {
    my ($rule_dir, $disable_file, $enable_file) = @_;

    print "update_preproc_rules()\n" if $debug;

    my $count = 0;
    my @lines;
    my %dsids;
    my %esids;
    
    @lines = read_file($disable_file);
    if (scalar(@lines) > 0) {
        @lines = parse_gid_sid(@lines);
        %dsids = map { $_ => 1 } @lines;
        $count += scalar(@lines);
    }
    print "disable count = $count\n" if $debug;

    @lines = read_file($enable_file);
    if (scalar(@lines) > 0) {
        @lines = parse_gid_sid(@lines);
        %esids = map { $_ => 1 } @lines;
        $count += scalar(@lines);
    }
    print "both count = $count\n" if $debug;

    return 0 if $count == 0;

    opendir(my $RIN_DIR, "$rule_dir") or die "Cannot open [$rule_dir]: $!";
    my @rule_files = grep /\.rules$/, readdir($RIN_DIR);
    closedir $RIN_DIR;

    my ($tot, $ok, $disabled, $comments, $err) = (0,0,0,0,0);

    foreach my $file (@rule_files) {
        open(my $RIN, '<', "$rule_dir/$file") or 
            die "Cannot open $rule_dir/$file: $!";
        my $output = '';
        while (<$RIN>) {
            my $line = $_;
            chomp $line;
            $tot++;

            if (/^#?\s*p[1234]action.*sid:\s?(\d+);\s?gid:\s?(\d+)/) {
                my $sid = $1;
                my $gid = $2;
                my $gsid = "$gid:$sid";
                if (/^#/) {
                    $disabled++;
                    if (defined $dsids{$gsid}) {
                        # already disabled
                        $dsids{$gsid}++;
                    }
                    if ($esids{$gsid}) {
                        print "enable [$gsid] [$file]\n" if $debug;
                        $line =~ s/^#\s*(.*)/$1/;
                        $esids{$gsid}++;
                    }
                } else {
                    $ok++;
                    if (defined $esids{$gsid}) {
                        # already enabled
                        $esids{$gsid}++;
                    }
                    if ($dsids{$gsid}) {
                        print "disable [$gsid] [$file]\n" if $debug;
                        $line = "# $line";
                        $dsids{$gsid}++;
                    }
                }
            } else {
                if ($line eq '') {
                    # whitespace
                } elsif ($line =~ /^#/) {
                    $comments++;
                } else {
                    $err++;
                    print "Warning: not found [$line] in [$file]\n";
                }
            }
            $output .= "$line\n";
        }
        close $RIN;
        open(my $ROUT, '>', "$rule_dir/$file") or 
            die "Cannot open $rule_dir/$file: $!";
        print $ROUT $output;
        close $ROUT;
    }

    foreach my $sid (sort keys %dsids) {  
        print "checking dsids [$sid]\n" if $debug;
        if ($dsids{$sid} == 1) {
            print "Warning: disable-sid [$sid] not found.\n";
        }
    }

    foreach my $sid (sort keys %esids) {  
        print "checking esids [$sid]\n" if $debug;
        if ($esids{$sid} == 1) {
            print "Warning: enable-sid [$sid] not found.\n";
        }
    }
    
    if ($debug) {
        print "\n";
        print "Total line: [$tot]\n";
        print "        ok: [$ok]\n";
        print "  comments: [$comments]\n";
        print "  disabled: [$disabled]\n";
        print "     error: [$err]\n\n";
    }

    return 0;
}

sub update_home_net {
    my ($conf_file, $file) = @_;
    
    my @networks = read_file($file);

    my ($cmd, $rc, $format);
    if (scalar(@networks) > 0) {
        $format = '[';
        foreach my $line (@networks) {
            chomp $line;
            $format .= "$line,";
        }
        chop $format;  # eat the last comma
        $format .= ']'; 
        $format =~ s|\/|\\\/|g;   # change '/' to '\/'
    } else {
        $format = 'any';
    }

    $cmd = "s/^\\(var HOME_NET\\).*\$/\\1 $format/";
    $cmd = "sed -i \'$cmd\' $conf_file";
    $rc = system("$cmd");

    if ($format eq 'any') {
        $cmd = "s/^\\(var EXTERNAL_NET\\).*\$/\\1 $format/";
    } else {
        $cmd = "s/^\\(var EXTERNAL_NET\\).*\$/\\1 \!\$HOME_NET/";
    }
    $cmd = "sed -i \'$cmd\' $conf_file";
    $rc = system("$cmd");

    return $rc;
}

sub update_exclude {
    my ($conf_file, $file) = @_;

    my @excludes = read_file($file);
    
    my ($cmd, $rc, $format);
    foreach my $exclude (@excludes) {
        $format = "s/^\\(include \\\$RULE_PATH\\/$exclude.*\\)\$/# \\1/";
        $cmd = "sed -i \'$format\' $conf_file";
        $rc = system($cmd);
        # print "cmd [$cmd] = $rc\n";
    }
    return 0;
}

sub del_exclude {
    my ($conf_file, $category) = @_;

    my ($cmd, $rc, $format);

    $format = "s/^\# \\(include \\\$RULE_PATH\\/$category.*\\)\$/\\1/";
    $cmd = "sed -i \'$format\' $conf_file";
    $rc = system($cmd);
    return $rc;
}

sub show_categories {
    my ($rule_dir) = @_;

    opendir(my $RIN_DIR, "$rule_dir") or die "Cannot open [$rule_dir]: $!";
    my @rule_files = grep /\.rules$/, readdir($RIN_DIR);
    closedir $RIN_DIR;
    if (scalar(@rule_files) < 1) {
        print "Error: no matching categories in [$rule_dir]\n";
        exit 1;
    } 
    print join("\n", @rule_files), "\n";
}


#
# main
#

my ($action, $rule_dir, $disable_file, $enable_file, $conf_file, $file, $value);
GetOptions('action=s'       => \$action,
           'ruledir=s'      => \$rule_dir,
           'disablefile=s'  => \$disable_file,
           'enablefile=s'   => \$enable_file,
           'conffile=s'     => \$conf_file,
           'file=s'         => \$file,
           'value=s'        => \$value,
          );
if (!defined($action)) {
    print "Error: must define action\n";
    exit 1;
}

my $rc = 1;

if ($action eq 'add-item') {
    if (!defined($file)) {
        print "Error: must define file\n";
        exit 1;
    }    
    if (!defined($value)) {
        print "Error: must define value\n";
        exit 1;
    }    

    print "Add [$file] [$value]\n" if $debug;
    add_item($file, $value);
    exit 0;
}

if ($action eq 'del-item') {
    if (!defined($file)) {
        print "Error: must define file\n";
        exit 1;
    }    
    if (!defined($value)) {
        print "Error: must define value\n";
        exit 1;
    }    
    print "Del sid [$file] [$value]\n" if $debug;
    del_item($file, $value);
    exit 0;
}

if ($action eq 'update-rules') {
    if (!defined($rule_dir)) {
        print "Error: must include ruledir\n";
        exit 1;
    }
    print "update rules\n" if $debug;
    $rc = update_rules($rule_dir, $disable_file, $enable_file);
}

if ($action eq 'update-preproc-rules') {
    if (!defined($rule_dir)) {
        print "Error: must include ruledir\n";
        exit 1;
    }
    print "update preproc_rules\n" if $debug;
    $rc = update_preproc_rules($rule_dir, $disable_file, $enable_file);
}

if ($action eq 'update-home-net') {
    if (!defined($conf_file)) {
        print "Error: must include conffile\n";
        exit 1;
    }
    if (!defined($file)) {
        print "Error: must include file\n";
        exit 1;
    }
    print "update-home-net\n" if $debug;
    $rc = update_home_net($conf_file, $file);
}

if ($action eq 'show-categories') {
    if (!defined($rule_dir)) {
        print "Error: must include ruledir\n";
        exit 1;
    }
    print "show-categories\n" if $debug;
    show_categories($rule_dir);
    exit 0;
}

if ($action eq 'update-exclude') {
    if (!defined($conf_file)) {
        print "Error: must include conffile\n";
        exit 1;
    }
    if (!defined($file)) {
        print "Error: must include file\n";
        exit 1;
    }
    print "update exclude\n" if $debug;
    $rc = update_exclude($conf_file, $file);
}

if ($action eq 'del-exclude') {
    if (!defined($conf_file)) {
        print "Error: must include conffile\n";
        exit 1;
    }
    if (!defined($value)) {
        print "Error: must define value\n";
        exit 1;
    }    

    print "del exclude [$value]\n" if $debug;
    $rc = del_exclude($conf_file, $value);
}

exit $rc;

# end of file
