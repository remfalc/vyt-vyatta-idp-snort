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

package Vyatta::Snort::Config;

use strict;
use lib '/opt/vyatta/share/perl5';
use Vyatta::Config;
use File::Copy;
use Sys::Hostname;
use File::Compare;
use Vyatta::IpTables::Mgr;
use Vyatta::Zone;

my $cfg_delim_begin = '# === BEGIN VYATTA SNORT CONFIG ===';
my $cfg_delim_end = '# === END VYATTA SNORT CONFIG ===';
my $post_fw_in_hook = 'VYATTA_POST_FW_IN_HOOK';
my $post_fw_fwd_hook = 'VYATTA_POST_FW_FWD_HOOK';
my $post_fw_out_hook = 'VYATTA_POST_FW_OUT_HOOK';
my @post_fw_hooks = ($post_fw_in_hook, $post_fw_fwd_hook, $post_fw_out_hook);
# non-user chain must be 'VYATTA_*_HOOK'
my $queue_prefix = 'VYATTA_SNORT_';
my $queue_suffix = '_HOOK';
my $SNORT_ALL_HOOK = $queue_prefix . 'all' . $queue_suffix;

my $SNORT_INIT = '/etc/init.d/snort';
my $SNORT_DONE = '/var/run/snort_vyatta_init.pid';

my %fields = (
  _tr_preset => undef,
  _tr_custom => undef,
  _tr_ipv6_preset => undef,
  _tr_ipv6_custom => undef,
  _p1act     => undef,
  _p2act     => undef,
  _p3act     => undef,
  _p4act     => undef,
  _au_oink   => undef,
  _au_hour   => undef,
  _au_vrtsub => undef,
  _is_empty  => 1,
  _db_type   => undef,
  _db_dbname => undef,
  _db_host   => undef,
  _db_user   => undef,
  _db_passwd => undef,
  _sl_fac    => undef,
  _sl_level  => undef,
  _local_log => 0,
  _prelude   => undef,
  _ins_all   => 'false',
  _ins_all_v6 => 'false',
  _exclude_categories => [],
  _disable_sids => [],
  _enable_sids => [],
  _internal_nets => [],
);

sub get_snort_all_hook {
  return $SNORT_ALL_HOOK;
}

sub new {
  my $that = shift;
  my $class = ref ($that) || $that;
  my $self = {
    %fields,
  };

  bless $self, $class;
  return $self;
}

sub setup {
  my ( $self ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel('content-inspection traffic-filter');
  $self->{_tr_preset} = $config->returnValue('preset');
  $self->{_tr_custom} = $config->returnValue('custom');
  $self->{_tr_ipv6_preset} = $config->returnValue('ipv6-preset');
  $self->{_tr_ipv6_custom} = $config->returnValue('ipv6-custom');

  $config->setLevel('content-inspection ips');
  my @nodes = $config->listNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_p1act} = $config->returnValue('actions priority-1');
  $self->{_p2act} = $config->returnValue('actions priority-2');
  $self->{_p3act} = $config->returnValue('actions priority-3');
  $self->{_p4act} = $config->returnValue('actions other');
  
  $self->{_au_oink} = $config->returnValue('auto-update oink-code');
  $self->{_au_hour} = $config->returnValue('auto-update update-hour');
  $self->{_au_vrtsub} = $config->exists('auto-update snortvrt-subscription');
  
  $config->setLevel('content-inspection ips modify-rules');
  foreach my $rule ($config->returnValues('exclude-category')){
    $self->{_exclude_categories} = [ @{$self->{_exclude_categories}}, $rule ];
  }
  foreach my $sid ($config->returnValues('disable-sid')){
    $self->{_disable_sids} = [ @{$self->{_disable_sids}}, $sid ];
  }
  foreach my $sid ($config->returnValues('enable-sid')){
    $self->{_enable_sids} = [ @{$self->{_enable_sids}}, $sid ];
  }
  foreach my $sid ($config->returnValues('internal-network')){
    $self->{_internal_nets} = [ @{$self->{_internal_nets}}, $sid ];
  }

  $config->setLevel('content-inspection ips log remote-db');
  $self->{_db_type}   = $config->returnValue('db-type');
  $self->{_db_dbname} = $config->returnValue('db-name');
  $self->{_db_host}   = $config->returnValue('host');
  $self->{_db_user}   = $config->returnValue('username');
  $self->{_db_passwd} = $config->returnValue('password');

  $config->setLevel('content-inspection ips log syslog');
  $self->{_sl_fac}   = $config->returnValue('facility');
  $self->{_sl_level} = $config->returnValue('level');

  $config->setLevel('content-inspection ips log');
  $self->{_prelude}  = $config->exists('prelude');

  $config->setLevel('content-inspection ips log');
  $self->{_local_log} = 1 if $config->exists('local');

  $config->setLevel('content-inspection inspect-all');
  $self->{_ins_all} = 'true' if $config->exists('enable');
  $self->{_ins_all_v6} = 'true' if $config->exists('ipv6-enable');

  return 0;
}

sub setupOrig {
  my ( $self ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel('content-inspection traffic-filter');
  $self->{_tr_preset} = $config->returnOrigValue('preset');
  $self->{_tr_custom} = $config->returnOrigValue('custom');
  $self->{_tr_ipv6_preset} = $config->returnOrigValue('ipv6-preset');
  $self->{_tr_ipv6_custom} = $config->returnOrigValue('ipv6-custom');

  $config->setLevel('content-inspection ips');
  my @nodes = $config->listOrigNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_p1act} = $config->returnOrigValue('actions priority-1');
  $self->{_p2act} = $config->returnOrigValue('actions priority-2');
  $self->{_p3act} = $config->returnOrigValue('actions priority-3');
  $self->{_p4act} = $config->returnOrigValue('actions other');
  
  $self->{_au_oink} = $config->returnOrigValue('auto-update oink-code');
  $self->{_au_hour} = $config->returnOrigValue('auto-update update-hour');
  $self->{_au_vrtsub} = $config->existsOrig('auto-update snortvrt-subscription');

  $config->setLevel('content-inspection ips modify-rules');
  foreach my $rule ($config->returnOrigValues('exclude-category')){
    $self->{_exclude_categories} = [ @{$self->{_exclude_categories}}, $rule ];
  }
  foreach my $sid ($config->returnOrigValues('disable-sid')){
    $self->{_disable_sids} = [ @{$self->{_disable_sids}}, $sid ];
  }
  foreach my $sid ($config->returnOrigValues('enable-sid')){
    $self->{_enable_sids} = [ @{$self->{_enable_sids}}, $sid ];
  }
  foreach my $net ($config->returnOrigValues('internal-network')){
    $self->{_internal_nets} = [ @{$self->{_internal_nets}}, $net ];
  }
  
  $config->setLevel('content-inspection ips log remote-db');
  $self->{_db_type}   = $config->returnOrigValue('db-type');
  $self->{_db_dbname} = $config->returnOrigValue('db-name');
  $self->{_db_host}   = $config->returnOrigValue('host');
  $self->{_db_user}   = $config->returnOrigValue('username');
  $self->{_db_passwd} = $config->returnOrigValue('password');

  $config->setLevel('content-inspection ips log syslog');
  $self->{_sl_fac}   = $config->returnOrigValue('facility');
  $self->{_sl_level} = $config->returnOrigValue('level');

  $config->setLevel('content-inspection ips log');
  $self->{_prelude}  = $config->existsOrig('prelude');

  $config->setLevel('content-inspection ips log');
  $self->{_local_log} = 1 if $config->existsOrig('local');

  $config->setLevel('content-inspection inspect-all');
  $self->{_ins_all} = 'true' if $config->existsOrig('enable');
  $self->{_ins_all_v6} = 'true' if $config->existsOrig('ipv6-enable');

  return 0;
}

sub checkAutoUpdate {
  my ($self, $orig) = @_;
  my $config = new Vyatta::Config;
  my $exists = ($orig) ?
                  $config->existsOrig('content-inspection ips auto-update')
                  : $config->exists('content-inspection ips auto-update');
  if ($exists) {
    if (!defined($self->{_au_hour})) {
      return ('NONE NONE',
              '"update-hour" must be set');
    }
    if (defined($self->{_au_oink}) && defined($self->{_au_vrtsub})) {
      return ('NONE NONE', 
              'cant set both "oink-code" and "snortvrt-subscription"');
    }
    if (!defined($self->{_au_oink}) && !defined($self->{_au_vrtsub})) {
      return ('NONE NONE', 
              'must define "oink-code" unless using "snortvrt-subscription"');
    }
  } else {
    return ('NONE NONE', undef);
  }

  my $FH;
  if (!open ($FH, '<', '/opt/vyatta/etc/ips/snort-ruleset')){
    return (undef, "Couldn't determine ruleset version");
  }
  my @ruleset = <$FH>;
  chomp @ruleset;
  (my $cur_ruleset) = @ruleset;

  my $file   = "/etc/cron.hourly/vyatta-ips-update";  
  my $output = '';
  if (!$orig && $self->{_au_oink}) {
    my $update_hour = $self->{_au_hour};
    my $oink        = $self->{_au_oink};
    
    $update_hour =~ s/^0*//;
    $update_hour = 0 if ($update_hour eq '');

    my $rules   = "snortrules-snapshot-$cur_ruleset.tar.gz";
    my $get_cmd = "/opt/vyatta/sbin/vyatta-get-snort-rules.pl $rules";

    $output  = '#!/bin/bash' . "\n#\n";
    $output .= '# autogenerated by Vyatta::Snort::Config.pm' ."\n#\n";
    $output .= '# cron job to automatically update the snort rules' . "\n\n";
    $output .= 'cur_hour=$(date +%-H)' . "\n";
    $output .= 'if [ "$cur_hour" != "' . $update_hour . '" ]; then' . "\n";
    $output .= '  # not the right hour. do nothing.' . "\n";
    $output .= '  exit 0' . "\n";
    $output .= 'fi' . "\n\n";
    $output .= 'if  ' . "$get_cmd " . ' ; then' . "\n";
    $output .= '   /opt/vyatta/sbin/vyatta-proc-snort-updates';
    $output .= " /tmp/$rules " . '>/dev/null 2>&1' . "\n";
    $output .= 'fi' . "\n\n";
  } elsif (!$orig && $self->{_au_vrtsub}) {
    my $update_hour = $self->{_au_hour};
  
    $update_hour =~ s/^0*//;
    $update_hour = 0 if ($update_hour eq '');

    my $base_dir = '/opt/vyatta/etc/ips';
    if (! -e $base_dir) {
        system("mkdir -p $base_dir");
    }

    my $rules   = "snortrules-snapshot-$cur_ruleset.tar.gz";
    my $get_cmd = "/opt/vyatta/sbin/vg_snort_update -q ";

    $output  = '#!/bin/bash' . "\n#\n";
    $output .= '# autogenerated by Vyatta::Snort::Config.pm' ."\n#\n";
    $output .= '# cron job to automatically update the ' . "\n";
    $output .= '# snort VRT subscription rules from vyatta portal' . "\n#\n";
    $output .= '# WARNING: You will NOT be able to download ' . "\n";
    $output .= '#          without a valid entitlement key.' . "\n";
    $output .= '#' . "\n\n";
    $output .= 'cur_hour=$(date +%-H)' . "\n";
    $output .= 'if [ "$cur_hour" != "' . $update_hour . '" ]; then' . "\n";
    $output .= '  # not the right hour. do nothing.' . "\n";
    $output .= '  exit 0' . "\n";
    $output .= 'fi' . "\n\n";
    $output .= 'if  ' . "$get_cmd " . ' ; then' . "\n";
    $output .= '   /opt/vyatta/sbin/vyatta-proc-snort-updates';
    $output .= " /tmp/$rules " . '>/dev/null 2>&1' . "\n";
    $output .= 'fi' . "\n\n";
  }

  if ($output ne '') {
    open(my $fh, '>', $file) || die "Couldn't open $file - $!";
    print $fh $output;
    close $fh;

    system("chmod 755 $file");
  }

  return ("$self->{_au_oink} $self->{_au_hour}", undef);
}

sub listsDiff {
  my @a = @{$_[0]};
  my @b = @{$_[1]};
  return 1 if ((scalar @a) != (scalar @b));
  while (my $a = shift @a) {
    my $b = shift @b; 
    return 1 if ($a ne $b);
  }
  return 0;
}

sub isDifferentFrom {
  my ($this, $that) = @_;

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_tr_preset} ne $that->{_tr_preset});
  return 1 if ($this->{_tr_custom} ne $that->{_tr_custom});
  return 1 if ($this->{_tr_ipv6_preset} ne $that->{_tr_ipv6_preset});
  return 1 if ($this->{_tr_ipv6_custom} ne $that->{_tr_ipv6_custom});
  return 1 if ($this->{_p1act} ne $that->{_p1act});
  return 1 if ($this->{_p2act} ne $that->{_p2act});
  return 1 if ($this->{_p3act} ne $that->{_p3act});
  return 1 if ($this->{_p4act} ne $that->{_p4act});
  return 1 if (listsDiff($this->{_exclude_categories}, $that->{_exclude_categories}));
  return 1 if (listsDiff($this->{_disable_sids}, $that->{_disable_sids}));
  return 1 if (listsDiff($this->{_enable_sids}, $that->{_enable_sids}));
  return 1 if (listsDiff($this->{_internal_nets}, $that->{_internal_nets}));

  return 1 if ($this->{_db_dbname} ne $that->{_db_dbname});
  return 1 if ($this->{_db_host}   ne $that->{_db_host});
  return 1 if ($this->{_db_user}   ne $that->{_db_user});
  return 1 if ($this->{_db_passwd} ne $that->{_db_passwd});

  return 1 if ($this->{_sl_fac}   ne $that->{_sl_fac});
  return 1 if ($this->{_sl_level} ne $that->{_sl_level});

  return 1 if ($this->{_prelude}  ne $that->{_prelude});

  return 1 if ($this->{_local_log} ne $that->{_local_log});

  return 1 if ($this->{_ins_all}   ne $that->{_ins_all});
  return 1 if ($this->{_ins_all_v6} ne $that->{_ins_all_v6});

  # ignore auto-update changes
  
  return 0;
}

sub needsRuleUpdate {
 my ($this, $that) = @_;
 return 1 if (listsDiff($this->{_exclude_categories}, $that->{_exclude_categories}));
 return 1 if (listsDiff($this->{_disable_sids}, $that->{_disable_sids}));
 return 1 if (listsDiff($this->{_enable_sids}, $that->{_enable_sids}));
 return 0;
}

sub isEmpty {
  my ($this) = @_;
  return $this->{_is_empty};
}



sub rule_num_sort {
  my ($a, $b) = (@_);
  my @aa = split /\s+/, $a;
  my @ab = split /\s+/, $b;
  return ($ab[0] <=> $aa[0]);
}

# Check whether a chain exists in the IPv4 filter table
sub chainExists {
  my $chain = shift;
  system("iptables -L $chain -vn >&/dev/null");
  return 0 if ($? >> 8);
  return 1;
}

# Check whether a chain exists in the IPv6 filter table
sub chainExistsIPv6 {
  my $chain = shift;
  system("ip6tables -L $chain -vn >&/dev/null");
  return 0 if ($? >> 8);
  return 1;
}

# Set up the chains for the "all" preset in both the IPv4 and IPv6 fiter
# tables.
sub setupIptables {
  my ($self) = @_;
  my %create_hash = ();
  my %create_hash_ipv6 = ();
  my @cmds = ();
  my $chain = $SNORT_ALL_HOOK;
  if (!chainExists($chain)) {
    $create_hash{'all'} = 1;
  }
  if (!chainExistsIPv6($chain)) {
    $create_hash_ipv6{'all'} = 1;
  }

  # set up preset "all" for IPv4 and IPv6
  my $queue_target = ipt_get_queue_target('SNORT');
  return "Error: Unknown queue target" if ! defined $queue_target;
  if ($create_hash{'all'}) {
    push @cmds,
      "iptables -N $chain",
      "iptables -A $chain -j $queue_target",
      "iptables -A $chain -j RETURN";
  }
  if ($create_hash_ipv6{'all'}) {
    push @cmds,
      "ip6tables -N $chain",
      "ip6tables -A $chain -j $queue_target",
      "ip6tables -A $chain -j RETURN";
  }

  # run all commands
  foreach (@cmds) {
    system("$_ >&/dev/null");
    return "Cannot setup iptables/ip6tables: ($_)" if ($? >> 8);
  }

  # return success
  return undef;
}

# Remove a rule jumping to a preset or custom chain located in the
# Vyatta post firewall hook chain of either the IPv4 or IPv6
# filter table.
sub removeChain {
    my ($cmd, $chain) = @_;

    foreach my $post_fw_hook (@post_fw_hooks) {
        my $grep = "grep ^[0-9] | grep $chain";
        my @lines = `$cmd -L $post_fw_hook -n --line-number | $grep`;
        @lines = sort rule_num_sort @lines;
        # rule number from high to low
        foreach (@lines) {
	    my ($num, $target) = split /\s+/;
	    next if ($target ne $chain);
	    system("$cmd -D $post_fw_hook $num");
	    return 'Cannot remove rule from iptables/ip6tables' if ($? >> 8);
        }
    }

    return undef;
}

# Remove all of the rules we've added located in the Vyatta post firewall
# hook chain of either the IPv4 or IPv6 filter table.
sub removeQueue {
  my ($self) = @_;
  my $ret1 = undef;
  my $ret2 = undef;

  my $chain = '';
  my $custom_chain = '';
  my $inspect_all = '';

  # ipv4 hook removal
  if (defined($self->{_tr_preset}) ||
      defined($self->{_tr_custom})) {
    $chain = $SNORT_ALL_HOOK;
    $custom_chain = $self->{_tr_custom}
	if defined $self->{_tr_custom};
  }
  $inspect_all = $self->{_ins_all};

  $ret1 = remove_ip_version_queue('ipv4', "$chain",
                                  "$custom_chain", "$inspect_all");

  $chain = '';
  $custom_chain = '';
  $inspect_all = '';
  # ipv6 hook removal
  if (defined($self->{_tr_ipv6_preset}) ||
      defined($self->{_tr_ipv6_custom})) {
    $chain = $SNORT_ALL_HOOK;
    $custom_chain = $self->{_tr_ipv6_custom}
	if defined $self->{_tr_ipv6_custom};
  }
  $inspect_all = $self->{_ins_all_v6};

  $ret2 = remove_ip_version_queue('ipv6', "$chain",
                                  "$custom_chain", "$inspect_all");

  if (defined($ret1)) {
      return $ret1;
  } elsif (defined($ret2)) {
      return $ret2;
  }

  # return success
  return undef;
}

sub remove_ip_version_queue {

  my ($ip_version, $chain, $custom_chain, $inspect_all) = @_;

  my $retval = undef;
  my $iptables_cmd = 'iptables';
  $iptables_cmd = 'ip6tables' if $ip_version eq 'ipv6';

  if (!($chain eq '')) {
    $retval = removeChain ("$iptables_cmd", $chain) if $inspect_all eq 'true';
  }

  my $queue_target = ipt_get_queue_target('SNORT');
  return "\nError: unknown queue target" if ! defined $queue_target;

  if (!($chain eq '') && !($custom_chain eq '')) {
    # remove custom-ruleset and put back $queue_target
    my $index = ipt_find_chain_rule("$iptables_cmd", 'filter',
                                    "$chain", "$custom_chain");
    if (! defined $index) {
      $retval .= "\nCannot find custom $iptables_cmd $custom_chain target";
    } else {
      # replace custom rule-set with $queue_target
      system("$iptables_cmd -R $chain $index -j $queue_target");
      $retval .= "\nCannot replace custom $iptables_cmd $custom_chain " .
		 "target" if ($? >> 8);
    }
  }

  return $retval;
}

# Validate configuration under "traffic-filter".
sub checkQueue {
  my ($self) = @_;
  return 'Must define "traffic-filter"'
    if (!defined($self->{_tr_preset}) && !defined($self->{_tr_custom}) &&
	!defined($self->{_tr_ipv6_preset}) && 
	!defined($self->{_tr_ipv6_custom}));

  return 'Cannot define both "preset" and "custom" for "traffic-filter"'
    if (defined($self->{_tr_preset}) && defined($self->{_tr_custom}));

  return 'Cannot define both "ipv6-preset" and "ipv6-custom" for "traffic-filter"'
    if (defined($self->{_tr_ipv6_preset}) && 
	defined($self->{_tr_ipv6_custom}));

  if (defined($self->{_tr_custom})) {
    my $chain = $self->{_tr_custom};
    system("iptables -L $chain -n >&/dev/null");
    if ($? >> 8) {
      return "Custom chain \"$chain\" is not valid in IPv4 filter table";
    }
  }

  if (defined($self->{_tr_ipv6_custom})) {
    my $chain = $self->{_tr_ipv6_custom};
    system("ip6tables -L $chain -n >&/dev/null");
    if ($? >> 8) {
      return "Custom chain \"$chain\" is not valid in IPv6 filter table";
    }
  }

  return undef;
}

# Based on the configuration parameters under "traffic-filter", add
# rules to the Vyatta post firewall hook of the IPv4 or IPv6 filter tables
# jumping to our preset or user defined chains.
sub addQueue {
  my ($self) = @_;
  my $chain = '';
  my $retval = undef;
  my $inspect_all = '';

  my $queue_target = ipt_get_queue_target('SNORT');
  return "\nError: unknown queue target" if ! defined $queue_target;

  # IPV4 QUEUE SETUP
  if (defined($self->{_tr_preset})) {
    $chain = $queue_target;
  } elsif (defined($self->{_tr_custom})) {
    $chain = $self->{_tr_custom};
  }
  $inspect_all = $self->{_ins_all};

  $retval = add_ip_version_queue('ipv4', "$chain", "$inspect_all");
  return $retval if defined $retval;

  # IPV6 QUEUE SETUP
  $chain = '';
  $inspect_all = '';
  if (defined($self->{_tr_ipv6_preset})) {
    $chain = $queue_target;
  } elsif (defined($self->{_tr_ipv6_custom})) {
    $chain = $self->{_tr_ipv6_custom};
  }
  $inspect_all = $self->{_ins_all_v6};

  $retval = add_ip_version_queue('ipv6', "$chain", "$inspect_all");
  return $retval if defined $retval;

  # return success
  return undef;
}

sub add_ip_version_queue {

  my ($ip_version, $chain, $inspect_all) = @_;

  my $queue_target = ipt_get_queue_target('SNORT');
  return "\nError: unknown queue target" if ! defined $queue_target;

  my $iptables_cmd = 'iptables';
  $iptables_cmd = 'ip6tables' if $ip_version eq 'ipv6';

  # if needed, set target to custom instead of the default QUEUE
  if (!($chain eq '') && !($chain eq $queue_target)) {
    my $index = ipt_find_chain_rule("$iptables_cmd", 'filter',
                                    "$SNORT_ALL_HOOK", "$queue_target");
    if (! defined $index) {
      return "Cannot find default $iptables_cmd $queue_target target";
    } else {
      # replace QUEUE target with custom rule-set
      system("$iptables_cmd -R $SNORT_ALL_HOOK $index -j $chain");
      return "Cannot replace default $iptables_cmd $queue_target target" if ($? >> 8);
    }
  }

  if (!($chain eq '') && $inspect_all eq 'true') {
      foreach my $post_fw_hook (@post_fw_hooks) {
          # insert rule at the end [before ACCEPT] if global inspection enabled
          my $rule_cnt = Vyatta::IpTables::Mgr::count_iptables_rules("$iptables_cmd",
                                'filter', $post_fw_hook);
          system("$iptables_cmd -I $post_fw_hook $rule_cnt -j $SNORT_ALL_HOOK");
          return 'Cannot insert rule into $iptables_cmd' if ($? >> 8);
      }
  }

  # success
  return undef;
}

# remove iptables queue rule(s) and stop snort (must be in this order).
# note: this should be invoked on "original" config.
# returns error message, or undef if success.
sub shutdownSnort {
  my ($self) = @_;
  my $err = $self->removeQueue();
  if (!defined($err)) {
    system("$SNORT_INIT stop >&/dev/null");
    if ($? >> 8) {
      $err = 'Stopping failed';
    }
  }
  return $err;
}

# start snort and add iptables queue rule(s) (must be in this order).
# note: this should be invoked on "new" config.
# returns error message, or undef if success.
sub startSnort {
  my ($self) = @_;

  my $err = $self->checkQueue();
  return $err if (defined($err));

  system("$SNORT_INIT start >&/dev/null");
  return 'Starting failed' if ($? >> 8);
  
  # wait for snort to finish initialization before adding queue rules
  # to avoid blocking traffic
  my $count = 0;
  $| = 1;
  while ($count < 120 && (! -f $SNORT_DONE)) {
    print '.';
    sleep 2;
    $count++;
  }
  return 'Initialization failed' if ($count == 120);

  # add iptables queue rule(s)
  return $self->addQueue();
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

sub modifyRules {
  my ($self) = @_;
  my $BASE_DIR = '/opt/vyatta/etc/ips';
  my $FH = undef;
  open($FH, '>', "$BASE_DIR/disable-sid") or return 1;
  foreach my $sid (@{$self->{_disable_sids}}){
    if ($sid =~ /.*?:.*/){
      print ${FH} "$sid\n";
    } else {
      print ${FH} "1:$sid\n";
    }
  }
  foreach my $rule (@{$self->{_exclude_categories}}){
    print ${FH} "$rule\n";
  }
  close $FH;
  open($FH, '>', "$BASE_DIR/enable-sid") or return 1;
  foreach my $sid (@{$self->{_enable_sids}}){
    if ($sid =~ /.*?:.*/){
      print ${FH} "$sid\n";
    } else {
      print ${FH} "1:$sid\n";
    }
  }
  close $FH;
  open($FH, '>', "$BASE_DIR/home-net") or return 1;
  foreach my $net (@{$self->{_internal_nets}}){
    print ${FH} "$net\n";
  }
  close $FH;

  my $cmd;
  # update exclude rules in new rules;
  $cmd = "/opt/vyatta/sbin/vyatta-proc-snort-changes" ;
  $cmd .= " /opt/vyatta/etc/ips/snortrules-snapshot-2853.tar.gz 2>&1";
  system($cmd);

  # update HOME_NET;
  $cmd = "/opt/vyatta/sbin/vyatta-modify-sids.pl";
  $cmd .= " --action=update-home-net"   ;
  $cmd .= " --conffile=/etc/snort/ips.conf";
  $cmd .= " --file=$BASE_DIR/home-net";
  system($cmd);

  # update EXTERNAL_NET;
  $cmd = "/opt/vyatta/sbin/vyatta-modify-sids.pl";
  $cmd .= " --action=update-external-net"   ;
  $cmd .= " --conffile=/etc/snort/ips.conf"  ;
  $cmd .= " --file=$BASE_DIR/external-net";
  system($cmd);

  return 0;
}

sub get_snort_conf {
  my ($self) = @_;

  return (undef, 'Action for "priority-1" not defined')
    if (!defined($self->{_p1act}));
  return (undef, 'Action for "priority-2" not defined')
    if (!defined($self->{_p2act}));
  return (undef, 'Action for "priority-3" not defined')
    if (!defined($self->{_p3act}));
  return (undef, 'Action for "other" not defined')
    if (!defined($self->{_p4act}));

  my $remote_logging = 0;
  my $local_logging  = $self->{_local_log};
  my ($loc_out_def, $rem_out_def);
  if ($self->{_db_dbname} or $self->{_sl_fac} or $self->{_predule}) {
      my ($rem_out_type, $rem_out_file);
      # barnyard2 expect unified2 format
      $rem_out_type = 'unified2';
      $rem_out_file = 'snort-unified2.log';
      $rem_out_def  = "output $rem_out_type: filename $rem_out_file, limit 1";
      $remote_logging = 1;
  } 

  if (! $remote_logging or $local_logging) {
      my ($loc_out_type, $loc_out_file);
      # just log alerts when storing locally
      $local_logging = 1;
      $loc_out_type = 'alert_unified';
      $loc_out_file = 'snort-unified.alert';
      $loc_out_def  = "output $loc_out_type: filename $loc_out_file, limit 1";
  }

  # drop rule
  my $rule_drop_def   = "{\n"
                      . "   type drop\n";
     $rule_drop_def  .= "   $loc_out_def\n" if $local_logging;
     $rule_drop_def  .= "   $rem_out_def\n" if $remote_logging;
     $rule_drop_def  .= "   output log_null\n" if ! $remote_logging;
     $rule_drop_def  .= "}\n";

  # sdrop rule
  my $rule_sdrop_def  = "{\n"
                      . "   type sdrop\n" 
                      . "   output log_null\n"
                      . "}\n";

  # alert rule
  my $rule_alert_def  = "{\n"
                      . "   type alert\n";
     $rule_alert_def  .= "   $loc_out_def\n" if $local_logging;
     $rule_alert_def  .= "   $rem_out_def\n" if $remote_logging;
     $rule_alert_def .= "   output log_null\n" if ! $remote_logging;
     $rule_alert_def .= "}\n";

  # pass rule
  my $rule_pass_def  = "{\n"
                     . "  type pass\n"
                     . "  output log_null\n"
                     . "}\n";

  my %ruletype_defs  = ( 'drop'  => $rule_drop_def,
                         'sdrop' => $rule_sdrop_def,
                         'alert' => $rule_alert_def,
                         'pass'  => $rule_pass_def );

  # add actions
  my $cfg = "\n## actions\n";
  my @actions = ($self->{_p1act}, $self->{_p2act}, $self->{_p3act},
                 $self->{_p4act});
  for my $i (1 .. 4) {
    my $action = $actions[$i - 1];
    my $def = $ruletype_defs{$action};
    return (undef, "Action type \"$action\" not defined") if (!defined($def));
    $cfg .= "ruletype p${i}action\n$def\n";
  }
  $cfg .= <<EOS;
## include clamav config
include clamav.config

## set output module
output log_null

EOS

  return ($cfg, undef);
}

sub removeCfg {
  my ($self, $file) = @_;
  # write empty between markers
  return writeCfg($self, $file, '');
}

sub writeCfg {
  my ($self, $file, $cfg) = @_;
  my $tmpf = $file;
  $tmpf =~ s/\//_/g;
  $tmpf = "/tmp/vyatta_$tmpf.$$";
  return "Cannot create temporary file $tmpf: $!" if (!copy($file, $tmpf));
  open(FIN, "<$file") or return "Cannot open $file: $!";
  open(FOUT, ">$tmpf") or return "Cannot open $tmpf: $!";
  my ($skip, $vbegin, $vend) = (0, 0, 0);
  while (<FIN>) {
    if (/^$cfg_delim_begin$/) {
      $skip = 1;
      $vbegin = 1;
      print FOUT;
      print FOUT $cfg;
      next;
    } elsif (/^$cfg_delim_end$/) {
      $skip = 0;
      $vend = 1;
    } elsif ($skip) {
      next;
    }
    print FOUT;
  }
  close FIN;
  close FOUT;
  return "Invalid config file: missing Vyatta marker(s)"
    if (!$vbegin || !$vend);
  return "Cannot create config file $file: $!" if (!move($tmpf, $file));
  # return success
  return undef;
}

sub print_str {
  my ($self) = @_;
  my $str = 'ips';
  $str .= "\n  preset " . $self->{_tr_preset};
  $str .= "\n  custom " . $self->{_tr_custom};
  $str .= "\n  p1act " . $self->{_p1act};
  $str .= "\n  p2act " . $self->{_p2act};
  $str .= "\n  p3act " . $self->{_p3act};
  $str .= "\n  p4act " . $self->{_p4act};
  $str .= "\n  empty " . $self->{_is_empty};
  $str .= "\n";

  return $str;
}

# this function is used to list all the directions in which content-inspection
# is enabled for a given IP version. Currently, inspection can be enabled
# EITHER globally OR on a per interface [in|out|local] and zone-pair basis
sub inspect_enabled_list {
  my ($self, $direction, $ip_version, $proposed_config) = @_;
  my $global_inspect = 'false';
  my @zone_pairs = ();
  my @interface_dirs = ();
  my $inspect_active = 'false';
  my $listnodesfunc = ($proposed_config ? 'listNodes' : 'listOrigNodes');
  my $existsnodefunc = ($proposed_config ? 'exists' : 'existsOrig');

  # check whether global-inspection is enabled
  if ($direction eq 'all-directions' || $direction eq 'global-inspect') {
    $global_inspect = $self->{_ins_all} if $ip_version eq 'v4';
    $global_inspect = $self->{_ins_all_v6} if $ip_version eq 'v6';
  }

  # get list of all interfaces that have inspection enabled
  if ($direction eq 'all-directions' || $direction eq 'interface-dir') {
    my $cfg = new Vyatta::Config;
    for (Vyatta::Interface::get_all_cfg_interfaces()) {
      my ($iname, $ipath) = ($_->{name}, $_->{path});
      for my $dir ($cfg->$listnodesfunc("$ipath content-inspection")) {
        my $enable = 'enable' if $ip_version eq 'v4';
        $enable = 'ipv6-enable' if $ip_version eq 'v6';
        my $ichain = $cfg->$existsnodefunc("$ipath content-inspection $dir $enable");
          push @interface_dirs, "$iname-$dir" if defined $ichain;
      }
    }
  }

  # get list of all zone-pairs that have inspection enabled
  if ($direction eq 'all-directions' || $direction eq 'zone-pair') {
    my @all_zones = Vyatta::Zone::get_all_zones($listnodesfunc);
    foreach my $zone (@all_zones) {
      my @from_zones = Vyatta::Zone::get_from_zones($listnodesfunc,$zone);
      foreach my $fromzone (@from_zones) {
        my $ruleset_type = 'name' if $ip_version eq 'v4';
        $ruleset_type = 'ipv6-name' if $ip_version eq 'v6';
        my $ips_enabled = Vyatta::Zone::is_ips_enabled(
                                $existsnodefunc,$zone,$fromzone,$ruleset_type);
        push @zone_pairs, "$zone-from-$fromzone" if defined $ips_enabled;
      }
    }
  }

  if ($global_inspect eq 'true' ||
      (scalar(@interface_dirs) != 0) ||
      (scalar(@zone_pairs) != 0))
  {
    $inspect_active = 'true';
  }

  # if $global_inspect is true then zone-pairs and intf_dirs must be empty
  return ($inspect_active, $global_inspect, \@interface_dirs, \@zone_pairs);
}

#
# barnyard2 crap below, maybe should move to Barnyard.pm
#

my $by_daemon = '/usr/bin/barnyard2';
my $by_logdir = '/var/log/barnyard2';
my $by_pid    = '/var/run/barnyard2_NULL.pid';
my $by_conf   = '/etc/snort/barnyard2.conf';
my $prelude   = 'profile=snort';

my %fac_hash = (
    'auth'     => 'LOG_AUTH',
    'authpriv' => 'LOG_AUTHPRIV',
    'cron'     => 'LOG_CRON',
    'daemon'   => 'LOG_DAEMON',
    'kern'     => 'LOG_KERN',
    'lpr'      => 'LOG_LPR',
    'mail'     => 'LOG_MAIL',
    'news'     => 'LOG_NEWS',
    'syslog'   => 'LOG_SYSLOG',
    'user'     => 'LOG_USER',
    'uucp'     => 'LOG_UUCP',
    'local0'   => 'LOG_LOCAL0',
    'local1'   => 'LOG_LOCAL1',
    'local2'   => 'LOG_LOCAL2',
    'local3'   => 'LOG_LOCAL3',
    'local4'   => 'LOG_LOCAL4',
    'local5'   => 'LOG_LOCAL5',
    'local6'   => 'LOG_LOCAL6',
);

my %level_hash = (
    'emerg'   => 'LOG_EMERG',
    'alert'   => 'LOG_ALERT',
    'crit'    => 'LOG_CRIT',
    'err'     => 'LOG_ERR',
    'warning' => 'LOG_WARNING',
    'notice'  => 'LOG_NOTICE',
    'info'    => 'LOG_INFO',
    'debug'   => 'LOG_DEBUG'
);

sub get_by_conf {
  my ($self) = @_;
    
  my $output = '';
  my $host = hostname();
  
  $output  = "#\n# autogenerated barnyard2.conf\n#\n \n";

  $output .= "config hostname: $host\n" if defined $host; 
  $output .= "config alert_with_interface_name\n";
  $output .= "config quiet\n";
  $output .= "config logdir: $by_logdir\n";
  $output .= "config archivedir: /dev/null\n";
  $output .= "config reference_file: /etc/snort/reference.config\n";
  $output .= "config gen_file: /etc/snort/gen-msg.map\n";
  $output .= "config sid_file: /etc/snort/sid-msg.map\n";
  $output .= "config waldo_file: $by_logdir/waldo\n";
  $output .= "config process_new_records_only\n";
  $output .= "\ninput unified2\n\n";

  return $output;
}

sub get_db_conf {
  my ($self) = @_;
    
  my $output = '';

  return $output if ! defined $self->{_db_type};
  return $output if ! defined $self->{_db_host};
  return $output if ! defined $self->{_db_dbname};
  return $output if ! defined $self->{_db_user};
  return $output if ! defined $self->{_db_passwd};

  $output .= "output database: log, $self->{_db_type}, "
           . "user=$self->{_db_user} "
           . "password=$self->{_db_passwd} "
           . "dbname=$self->{_db_dbname} "
           . "host=$self->{_db_host}\n";

  return $output;
}

sub get_sl_conf {
  my ($self) = @_;
    
  my $output = '';

  return $output if ! defined $self->{_sl_fac};
  return $output if ! defined $self->{_sl_level};

  # output alert_syslog: severity facility 

  my ($fac, $level);
  $fac   = $fac_hash{$self->{_sl_fac}};
  $level = $level_hash{$self->{_sl_level}};

  return $output if ! defined $fac or ! defined $level;

  $output .= "output alert_syslog: $level $fac\n";

  return $output;
}

sub get_prelude_conf {
  my ($self) = @_;
    
  my $output = '';

  return $output if ! defined $self->{_prelude};

  # output alert_prelude: profile=snort 

  $output .= "#output alert_prelude: $prelude\n";

  return $output;
}

sub is_same_as_file {
    my ($file, $value) = @_;

    return if ! -e $file;

    my $mem_file = '';
    open my $MF, '+<', \$mem_file or die "couldn't open memfile $!\n";
    print $MF $value;
    seek($MF, 0, 0);
    
    my $rc = compare($file, $MF);
    return 1 if $rc == 0;
    return;
}

sub conf_write_file {
    my ($file, $config) = @_;

    # Avoid unnecessary writes.  At boot the file will be the
    # regenerated with the same content.
    return if is_same_as_file($file, $config);

    open(my $fh, '>', $file) || die "Couldn't open $file - $!";
    print $fh $config;
    close $fh;
    return 1;
}

sub is_running {
    my ($pid_file) = @_;

    if (-f $pid_file) {
	my $pid = `cat $pid_file`;
	$pid =~ s/\s+$//;  # chomp doesn't remove nl
	my $ps = `ps -p $pid -o comm=`;
	if (defined($ps) && $ps ne "") {
	    return $pid;
	} 
    }
    return 0;
}

my $by_watch     = '/opt/vyatta/sbin/vyatta-barn-watcher.pl';
my $by_watch_pid = '/var/run/vyatta-barn-watcher';

sub handle_barn {
  my ($self, $orig) = @_;

  my $output = '';
  my $pid;

  $output .= get_db_conf($self);
  $output .= get_sl_conf($self);
  $output .= get_prelude_conf($self);

  if ($output ne '') {
      my $by_output = get_by_conf($self);
      $output = $by_output . $output;

      $pid = is_running($by_watch_pid);
      if (!conf_write_file($by_conf, $output) and $pid > 0) {
          return 0;
      }
      if ($pid > 0) {
          system("kill -SIGINT $pid");
      }
      my ($cmd, $rc);
      system("sudo rm -f /var/log/snort/snort-unified*");
      if ($ENV{'VYATTA_BOOTING'} ne 'yes') {
          $cmd = "$by_daemon -c $by_conf -d /var/log/snort -T -q";
          $rc = system("sudo $cmd");
          if ($rc) {
              print "Error: testing $by_conf\n";
              system("sudo mv $by_conf /tmp");
              return 1;
          }
      } 
      $cmd = "$by_watch --pidfile $by_watch_pid ";
      if (defined $self->{_db_host}) {
          $cmd .= "--ipaddr $self->{_db_host}";
      }
      print "Starting barnyard2 daemon\n";
      system("sudo $cmd > /dev/null 2>&1 &");
  } else {
      $pid = is_running($by_watch_pid);
      if ($pid > 0) {
          print "Stopping barnyard2\n";
          system("kill -INT $pid");
      } 
      system("sudo rm -f $by_conf");
      system("sudo rm -f /var/log/snort/snort-unified*");
      system("sudo rm -f $by_logdir/waldo");
  }
}

1;

