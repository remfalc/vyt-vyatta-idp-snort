#!/usr/bin/perl
#
# Module: vyatta-intf-inspect.pl
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
# Author: Mohit Mehta
# Date: October 2010
# Description: Script to configure IPS in a certain direction on an interface
#
# **** End License ****
#

use lib "/opt/vyatta/share/perl5";
use warnings;
use strict;

use Vyatta::Snort::Config;
use Vyatta::Config;
use Vyatta::IpTables::Mgr;
use Getopt::Long;
use Vyatta::Zone;

# post firewall hooks for each CLI direction in the filter table
my %dir_postfw_hook_hash = (
  'in'    => 'VYATTA_POST_FW_FWD_HOOK',
  'out'   => 'VYATTA_POST_FW_FWD_HOOK',
  'local' => 'VYATTA_POST_FW_IN_HOOK'
);

# snort hooks for each CLI direction in the filter table
my %dir_snort_hook_hash = (
  'in'    => 'VYATTA_SNORT_IN_HOOK',
  'out'   => 'VYATTA_SNORT_OUT_HOOK',
  'local' => 'VYATTA_SNORT_LOCAL_HOOK'
);

# iptables interface direction flag based on CLI direction
my %dir_ipt_flag_hash = (
  'in'    => '-i',
  'out'   => '-o',
  'local' => '-i'
);

# mapping from config node to netfilter table
my %table_hash = (
  'enable'      => 'filter',
  'ipv6-enable' => 'filter'
);

# mapping from config node to iptables command.
my %cmd_hash = (
  'enable'      => 'iptables',
  'ipv6-enable' => 'ip6tables'
);

# mapping from config node to IP version string.
my %ip_version_hash = (
  'enable'      => 'ipv4',
  'ipv6-enable' => 'ipv6'
);

# SNORT_ALL_HOOK
my $queue_prefix   = 'VYATTA_SNORT_';
my $queue_suffix   = '_HOOK';
my $SNORT_ALL_HOOK = $queue_prefix . 'all' . $queue_suffix;

# debug flags
my $debug_flag  = "false";
my $syslog_flag = "false";

my $logger = 'sudo logger -t vyatta-intf-inspect.pl -p local0.warn --';

sub run_cmd {
  my $cmd   = shift;
  my $error = system("$cmd");

  if ( $syslog_flag eq "true" ) {
    my $func = ( caller(1) )[3];
    system("$logger [$func] [$cmd] = [$error]");
  }
  if ( $debug_flag eq "true" ) {
    my $func = ( caller(1) )[3];
    print "[$func] [$cmd] = [$error]\n";
  }
  return $error;
}

sub log_msg {
  my $message = shift;

  print "DEBUG: $message" if $debug_flag eq 'true';
  system("$logger DEBUG: \"$message\"") if $syslog_flag eq 'true';
}

sub setup_snort_hook {

  my ( $cli_ip_ver, $direction ) = @_;
  my ( $cmd, $error );
  my $default_policy = 'RETURN';

  log_msg "setup_snort_hook called\n";

  # create snort hook for the specified CLI direction
  $cmd = "sudo $cmd_hash{$cli_ip_ver} -t $table_hash{$cli_ip_ver} "
    . "-N $dir_snort_hook_hash{$direction} >&/dev/null";

  $error = run_cmd($cmd);
  return "Error: $ip_version_hash{$cli_ip_ver} $dir_snort_hook_hash{$direction}"
    . " creation failed [$error]"
    if $error;

  # setup default policy for the created snort hook
  $cmd = "sudo $cmd_hash{$cli_ip_ver} -t $table_hash{$cli_ip_ver} "
    . "-A $dir_snort_hook_hash{$direction} -j $default_policy >&/dev/null";

  $error = run_cmd($cmd);
  return "Error: $ip_version_hash{$cli_ip_ver} $dir_snort_hook_hash{$direction}"
    . " default-policy creation failed [$error]"
    if $error;

  # put the snort hook in appropriate post firewall hook
  # if direction is out then insert rule after in hook
  my $insert_index = '1';
  my $index = Vyatta::IpTables::Mgr::ipt_find_chain_rule(
                $cmd_hash{$cli_ip_ver},
                $table_hash{$cli_ip_ver},
                $dir_postfw_hook_hash{$direction},
                $dir_snort_hook_hash{'in'})
                if $direction eq 'out';

  $insert_index = ++$index if defined $index;

  $cmd =
      "sudo $cmd_hash{$cli_ip_ver} -t $table_hash{$cli_ip_ver} "
    . "-I $dir_postfw_hook_hash{$direction} $insert_index "
    . "-j $dir_snort_hook_hash{$direction} >&/dev/null";

  $error = run_cmd($cmd);
  return "Error: $ip_version_hash{$cli_ip_ver} $dir_snort_hook_hash{$direction}"
    . " insertion into $dir_postfw_hook_hash{$direction} failed [$error]"
    if $error;

  log_msg "done with setup_snort_hook\n";

  # success
  return;

}

sub teardown_snort_hook {

  my ( $cli_ip_ver, $direction ) = @_;
  my ( $cmd, $error );

  log_msg "teardown_snort_hook called\n";

  # remove snort hook from appropriate post firewall hook
  $cmd =
      "sudo $cmd_hash{$cli_ip_ver} -t $table_hash{$cli_ip_ver} "
    . "-D $dir_postfw_hook_hash{$direction} "
    . "-j $dir_snort_hook_hash{$direction} >&/dev/null";

  $error = run_cmd($cmd);
  return "Error: $ip_version_hash{$cli_ip_ver} $dir_snort_hook_hash{$direction}"
    . " removal from $dir_postfw_hook_hash{$direction} failed [$error]"
    if $error;

  # flush rules from snort hook
  $cmd = "sudo $cmd_hash{$cli_ip_ver} -t $table_hash{$cli_ip_ver} "
    . "-F $dir_snort_hook_hash{$direction} >&/dev/null";

  $error = run_cmd($cmd);
  return "Error: $ip_version_hash{$cli_ip_ver} $dir_snort_hook_hash{$direction}"
    . " flush of rules failed [$error]"
    if $error;

  # delete snort hook
  $cmd = "sudo $cmd_hash{$cli_ip_ver} -t $table_hash{$cli_ip_ver} "
    . "-X $dir_snort_hook_hash{$direction} >&/dev/null";

  $error = run_cmd($cmd);
  return "Error: $ip_version_hash{$cli_ip_ver} $dir_snort_hook_hash{$direction}"
    . " deletion failed [$error]"
    if $error;

  log_msg "done with teardown_snort_hook\n";

  # success
  return;

}

sub enable_intf_inspect {
  my ( $cli_ip_ver, $intf, $direction ) = @_;
  my ( $cmd, $error );
  my $snort_target = $SNORT_ALL_HOOK;

  log_msg 
    "Enable inspection on intf:$intf, dir:$direction, IP_VER:$cli_ip_ver\n";

  # call setup_snort_hook if needed
  if (
    !Vyatta::IpTables::Mgr::chain_referenced(
      $table_hash{$cli_ip_ver}, $dir_snort_hook_hash{$direction},
      $cmd_hash{$cli_ip_ver}
    )
    )
  {
    $error = setup_snort_hook( $cli_ip_ver, $direction );
    return $error if $error;
  }

  # enable inspection on this interface
  $cmd =
      "sudo $cmd_hash{$cli_ip_ver} -t $table_hash{$cli_ip_ver} "
    . "-I $dir_snort_hook_hash{$direction} $dir_ipt_flag_hash{$direction}"
    . " $intf -j $snort_target >&/dev/null";

  $error = run_cmd($cmd);
  return "Error: $ip_version_hash{$cli_ip_ver} inspection on $direction $intf"
    . " failed [$error]"
    if $error;

  log_msg
    "inspection enabled on intf:$intf, dir:$direction, IP_VER:$cli_ip_ver\n";

  return;
}

sub disable_intf_inspect {
  my ( $cli_ip_ver, $intf, $direction ) = @_;
  my ( $cmd, $error );
  my $default_policy_rule_num = 1;    # only one rule with RETURN target
  my $snort_target = $SNORT_ALL_HOOK;

  log_msg 
    "disable inspection on intf:$intf, dir:$direction, IP_VER:$cli_ip_ver\n";

  # disable inspection on this interface
  $cmd =
      "sudo $cmd_hash{$cli_ip_ver} -t $table_hash{$cli_ip_ver} "
    . "-D $dir_snort_hook_hash{$direction} $dir_ipt_flag_hash{$direction} "
    . " $intf -j $snort_target >&/dev/null";

  $error = run_cmd($cmd);
  return "Error: disabling $ip_version_hash{$cli_ip_ver} inspection on"
    . " $direction $intf failed [$error]"
    if $error;

  # call teardown_snort_hook if needed
  my $cnt = Vyatta::IpTables::Mgr::count_iptables_rules(
    $cmd_hash{$cli_ip_ver},
    $table_hash{$cli_ip_ver},
    $dir_snort_hook_hash{$direction}
  );
  if ( $cnt == $default_policy_rule_num ) {
    $error = teardown_snort_hook( $cli_ip_ver, $direction );
    return $error if $error;
  }

  log_msg
    "inspection disabled on intf:$intf, dir:$direction, IP_VER:$cli_ip_ver\n";

  return;
}

sub chk_global_inspect {

  my ($cli_ip_ver) = @_;
  my ($error);

  my $CI_config = new Vyatta::Snort::Config;
  $CI_config->setup();

  if ( $ip_version_hash{$cli_ip_ver} eq 'ipv4' ) {
    return "Content-inspection enabled for all IPv4 traffic. "
      . "Cannot set it on a per-interface basis."
      if $CI_config->{_ins_all} eq 'true';
  } elsif ( $ip_version_hash{$cli_ip_ver} eq 'ipv6' ) {
    return "Content-inspection enabled for all IPv6 traffic. "
      . "Cannot set it on a per-interface basis."
      if $CI_config->{_ins_all_v6} eq 'true';
  }

  return;
}

sub chk_intf_in_zone {
  my ($int_name) = @_;

  # make sure interface is not being used in a zone
  my @all_zones = Vyatta::Zone::get_all_zones("listNodes");
  foreach my $zone (@all_zones) {
    my @zone_interfaces =
       Vyatta::Zone::get_zone_interfaces("returnValues", $zone);
    if (scalar(grep(/^$int_name$/, @zone_interfaces)) > 0) {
      return "interface $int_name is defined under zone $zone. " .
             "Cannot apply content-inspection to it";
    }
  }

  return;
}

#
# main
#

my ( $action, $cli_ip_ver, $intf, $direction );

GetOptions(
  "action=s"     => \$action,
  "cli-ip-ver=s" => \$cli_ip_ver,
  "intf=s"       => \$intf,
  "direction=s"  => \$direction,
);

die "undefined action" if !defined $action;

my ( $error, $warning );

( $error, $warning ) = chk_intf_in_zone($intf)
  if $action eq 'chk-intf-in-zone';

( $error, $warning ) = enable_intf_inspect( $cli_ip_ver, $intf, $direction )
  if $action eq 'enable-intf-inspect';

( $error, $warning ) = disable_intf_inspect( $cli_ip_ver, $intf, $direction )
  if $action eq 'disable-intf-inspect';

if ( defined $warning ) {
  print "$warning\n";
}

if ( defined $error ) {
  print "$error\n";
  exit 1;
}

exit 0;

# end of file
