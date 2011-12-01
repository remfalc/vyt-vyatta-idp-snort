#!/usr/bin/perl
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
# Date: August 2010
# Description: Script to automatically generate per-interface content-inspection
#              templates. Based off per-interface firewall template generation
#              in vyatta-cfg-firewall package
#
#
# **** End License ****
#

use strict;
use warnings;

# Set to 1 to enable debug output.
#
my $debug = 0;

# This hash maps the root of the tree of content-inspection templates for each
# interface into the variable reference that each of the node.def files in
# that tree will need to use to get the interface name.  The keys of this hash
# are the partial pathname under the config template tree "interfaces/".
#
my %interface_hash = (
  'adsl/node.tag/pvc/node.tag/bridged-ethernet' => '$VAR(../../../../../@)',
  'adsl/node.tag/pvc/node.tag/classical-ipoa'   => '$VAR(../../../../../@)',
  'adsl/node.tag/pvc/node.tag/pppoa/node.tag'   => 'pppoa$VAR(../../../@)',
  'adsl/node.tag/pvc/node.tag/pppoe/node.tag'   => 'pppoe$VAR(../../../@)',

  'bonding/node.tag'              => '$VAR(../../../@)',
  'bonding/node.tag/vif/node.tag' => '$VAR(../../../../@).$VAR(../../../@)',
  'bonding/node.tag/vrrp/vrrp-group/node.tag/interface' => '$VAR(../../../../../../@)v$VAR(../../../../@)',

  'ethernet/node.tag'                => '$VAR(../../../@)',
  'ethernet/node.tag/pppoe/node.tag' => 'pppoe$VAR(../../../@)',
  'ethernet/node.tag/vrrp/vrrp-group/node.tag/interface' => '$VAR(../../../../../../@)v$VAR(../../../../@)',
  'ethernet/node.tag/vif/node.tag'   => '$VAR(../../../../@).$VAR(../../../@)',
  'ethernet/node.tag/vif/node.tag/pppoe/node.tag' => 'pppoe$VAR(../../../@)',
  'ethernet/node.tag/vif/node.tag/vrrp/vrrp-group/node.tag/interface' =>
           '$VAR(../../../../../../../@).$VAR(../../../../../../@)v$VAR(../../../../@)',

  'pseudo-ethernet/node.tag'                      => '$VAR(../../../@)',

#  'pseudo-ethernet/node.tag/vif/node.tag' => '$VAR(../../../../@).$VAR(../../../@)',

  'wireless/node.tag'              => '$VAR(../../../@)',
  'wireless/node.tag/vif/node.tag' => '$VAR(../../../../@).$VAR(../../../@)',

  'input/node.tag'   => '$VAR(../../../@)',
  'tunnel/node.tag'  => '$VAR(../../../@)',
  'bridge/node.tag'  => '$VAR(../../../@)',
  'openvpn/node.tag' => '$VAR(../../../@)',

  'multilink/node.tag/vif/node.tag' => '$VAR(../../../../@)',

  'serial/node.tag/cisco-hdlc/vif/node.tag' =>
    '$VAR(../../../../../@).$VAR(../../../@)',
  'serial/node.tag/frame-relay/vif/node.tag' =>
    '$VAR(../../../../../@).$VAR(../../../@)',
  'serial/node.tag/ppp/vif/node.tag' =>
    '$VAR(../../../../../@).$VAR(../../../@)',

  'wirelessmodem/node.tag' => '$VAR(../../../@)',
);

# The subdirectory where the generated templates will go
my $template_subdir = "generated-templates/interfaces";

# The name of the subdir under each interface holding the content-inspection tree
my $CI_subdir = "content-inspection";

# The name of the config file we will be writing.
my $node_file = "node.def";

sub mkdir_p {
  my $path = shift;

  return 1 if ( mkdir($path) );

  my $pos = rindex( $path, "/" );
  return unless $pos != -1;
  return unless mkdir_p( substr( $path, 0, $pos ) );
  return mkdir($path);
}

# Generate the template file located at the root of the CI tree
# under an interface.  This template just provides a help message.
#
sub gen_CI_template {
  my ($if_tree) = @_;
  my $path = "${template_subdir}/${if_tree}/${CI_subdir}";

  ( -d $path )
    or mkdir_p($path)
    or die "Can't make directory $path: $!";

  open my $tp, '>', "$path/$node_file"
    or die "Can't create $path/$node_file: $!";
  my $date = `date`;
  print $tp "# Template generated at: $date\n";
  print "${if_tree}\n";
  if (${if_tree} eq 'openvpn/node.tag'){
    print $tp 
      "priority: 461 #after content-inspection, before address configuration\n";
  } elsif ( $if_tree =~ /vrrp/) {
    print $tp 
      "priority: 801 #after vrrp\n"
  } else {
    print $tp 
      "priority: 381 #after content-inspection, before address configuration\n";
  }
  print $tp "help: Content-inspection options\n";
  close $tp
    or die "Can't write $path/$node_file: $!";
}

# Map a content-inspection "direction" into a sub-string that we will use to compose
# the help message.
#
my %direction_help_hash = (
  "in"    => "forwarded packets on inbound interface",
  "out"   => "forwarded packets on outbound interface",
  "local" => "packets destined for this router",
);

# Generate the template file located under the "direction" node in the
# content-inspection tree under an interface.
#
sub gen_direction_template {
  my ( $if_tree, $direction ) = @_;
  my $path = "${template_subdir}/${if_tree}/${CI_subdir}/${direction}";

  ( -d $path )
    or mkdir_p($path)
    or die "Can't make directory $path: $!";

  open my $tp, '>', "$path/$node_file"
    or die "Can't open $path/$node_file: $!";

  my $date = `date`;
  print $tp <<EOF;
# Template generated at: $date
help: Option to inspect $direction_help_hash{$direction}

# in future, when ipv6 is enabled, message below will say either 
# 'enable' or 'ipv6-enable' needs to be set
commit:expression: \$VAR(./enable) != "" || \$VAR(./ipv6-enable) != ""; 
	"Need to set 'enable' to inspect IPV4 traffic on \$VAR(../../@)"

EOF

  close $tp
    or die "Can't write $path/$node_file: $!";
}

# Map a content-inspection "direction" into the term we will use for it in help
# messages.
#
my %direction_term_hash = (
  "in"    => "inbound",
  "out"   => "outbound",
  "local" => "local",
);

# Map a content-inspection option into the string that we will use to describe
# it in help messages.
#
my %option_help_hash = (
  "enable"       => "IPv4 content-inspection",
  ".ipv6-enable" => "IPv6 content-inspection",
);

# Generate the template file at the leaf of the per-interface C-I tree.
# This template contains all the code to activate or deactivate a C-I
# option on an interface for a particular option and direction.
#
sub gen_template {
  my ( $if_tree, $direction, $option, $if_name ) = @_;

  if ($debug) {
    print "debug: direction=$direction option=$option\n";
  }

  my $template_dir =
    "${template_subdir}/${if_tree}/${CI_subdir}/${direction}/${option}";

  if ($debug) {
    print "debug: template_dir=$template_dir\n";
  }

  ( -d $template_dir )
    or mkdir_p($template_dir)
    or die "Can't make directory $template_dir: $!";

  open my $tp, '>', "${template_dir}/${node_file}"
    or die "Can't open ${template_dir}/${node_file}:$!";

  my $date = `date`;
  my $tf_preset = 'preset';
  my $tf_custom = 'custom';
  $tf_preset = 'ipv6-preset' if $option eq 'ipv6-enable';
  $tf_custom = 'ipv6-custom' if $option eq 'ipv6-enable';

  print $tp <<EOF;
# Template generated at: $date
help: Option to enable $direction_term_hash{$direction} $option_help_hash{$option} for interface

# check if traffic-filter is set
commit:expression:
exec "
if cli-shell-api existsEffective				\\
content-inspection traffic-filter $tf_preset; then		\\
        exit 0;						\\
fi;								\\
if cli-shell-api existsEffective				\\
content-inspection traffic-filter $tf_custom; then		\\
        exit 0;						\\
fi;								\\
echo $option_help_hash{$option} traffic-filter not set;	\\
exit 1"

# make sure inspect-all is not enabled
commit:expression:
exec "
if ! cli-shell-api existsEffective				\\
content-inspection inspect-all $option; then			\\
        exit 0;						\\
fi;								\\
echo $option_help_hash{$option} enabled for all traffic. Not 	\\
allowed to configure inspection on a per-interface basis.;	\\
exit 1"

create:
        if ! /opt/vyatta/sbin/vyatta-intf-inspect.pl	\\
          --action=chk-intf-in-zone			\\
          --intf=$interface_hash{$if_tree}; then
          exit 1
        fi

        if ! /opt/vyatta/sbin/vyatta-intf-inspect.pl	\\
          --action=enable-intf-inspect			\\
          --intf=$interface_hash{$if_tree}              \\
          --direction=\$VAR(../@)			\\
          --cli-ip-ver=$option; then
          exit 1
        fi

delete:
        if ! /opt/vyatta/sbin/vyatta-intf-inspect.pl	\\
          --action=disable-intf-inspect			\\
          --intf=$interface_hash{$if_tree}              \\
          --direction=\$VAR(../@)			\\
          --cli-ip-ver=$option; then
          exit 1
        fi

EOF

  close $tp
    or die "Can't write ${template_dir}/${node_file}:$!";
}

# The content-inspection types
my @CI_options = ( "enable", ".ipv6-enable" );

# The content-inspection "directions"
my @CI_directions = ( "in", "out", "local" );

print "Generating interface templates...\n";

foreach my $if_tree ( keys %interface_hash ) {
  my $if_name = $interface_hash{$if_tree};

  if ($debug) {
    print "\ndebug: if_tree=$if_tree if_name=$if_name \n";
  }

  gen_CI_template($if_tree);
  for my $direction (@CI_directions) {
    gen_direction_template( $if_tree, $direction );
    foreach my $option (@CI_options) {
      gen_template( $if_tree, $direction, $option, $if_name );
    }
  }
}

print "Done.\n";
