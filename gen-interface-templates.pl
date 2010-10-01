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

  'ethernet/node.tag'                => '$VAR(../../../@)',
  'ethernet/node.tag/pppoe/node.tag' => 'pppoe$VAR(../../../@)',
  'ethernet/node.tag/vif/node.tag'   => '$VAR(../../../../@).$VAR(../../../@)',
  'ethernet/node.tag/vif/node.tag/pppoe/node.tag' => 'pppoe$VAR(../../../@)',
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
  print $tp
    "# Template generated at: $date\nhelp: Content-inspection options\n";
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
# content-inspection tree under an interface.  This template just provides a help
# message.
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
  print $tp "# Template generated at: $date\n";
  print $tp "help: Option to inspect $direction_help_hash{$direction}\n";
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

  print $tp <<EOF;
# Template generated at: $date
help: Option to enable $direction_term_hash{$direction} $option_help_hash{$option} for interface

create:
        if ! /opt/vyatta/sbin/vyatta-intf-inspect.pl	\\
          --action=chk-global-inspect			\\
          --cli-ip-ver=$option; then
          exit 1
        else
          if ! /opt/vyatta/sbin/vyatta-intf-inspect.pl	\\
            --action=enable-intf-inspect		\\
            --intf=\$VAR(../../../@)			\\
            --direction=\$VAR(../@)			\\
            --cli-ip-ver=$option; then
            exit 1
          fi
        fi

delete:
        if ! /opt/vyatta/sbin/vyatta-intf-inspect.pl	\\
          --action=disable-intf-inspect			\\
          --intf=\$VAR(../../../@)			\\
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
