cfgdir		  = $(datadir)/vyatta-cfg/templates
opdir		  = $(datadir)/vyatta-op/templates
share_perl5dir	  = $(datarootdir)/perl5/Vyatta/Snort
bin_sudo_usersdir = $(bindir)/sudo-users
cron_hourlydir    = /etc/cron.hourly
curverdir         = $(sysconfdir)/config-migrate/current

curver_DATA = cfg-version/content-inspection@2

sbin_SCRIPTS = scripts/vyatta-update-snort.pl
sbin_SCRIPTS += scripts/vyatta-proc-snort-rules.pl
sbin_SCRIPTS += scripts/vyatta-update-inspection.pl
sbin_SCRIPTS += scripts/vyatta-show-ips.pl
sbin_SCRIPTS += scripts/vyatta-proc-snort-updates
sbin_SCRIPTS += scripts/vyatta-proc-snort-changes
sbin_SCRIPTS += scripts/vyatta-get-snort-rules.pl
sbin_SCRIPTS += scripts/vyatta-modify-sids.pl
sbin_SCRIPTS += scripts/vyatta-intf-inspect.pl
sbin_SCRIPTS += scripts/vyatta-show-ips-class.pl
sbin_SCRIPTS += scripts/vyatta-barn-watcher.pl

bin_sudo_users_SCRIPTS  = scripts/vyatta-op-update-rules.pl
bin_sudo_users_SCRIPTS  += pulledpork/pulledpork.pl

share_perl5_DATA = lib/Vyatta/Snort/Config.pm
share_perl5_DATA += lib/Vyatta/Snort/UnifiedLog.pm

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

all-local:
	./gen-interface-templates.pl

clean-local:
	rm -rf generated-templates

install-exec-hook:
	mkdir -p $(DESTDIR)/opt/vyatta/etc/ips/work
	mkdir -p $(DESTDIR)/etc/snort/rules
	cp -f scripts/local.rules $(DESTDIR)/etc/snort/rules/
	cp -f scripts/snort-ruleset $(DESTDIR)/opt/vyatta/etc/ips/
	cp -f scripts/snort-categories $(DESTDIR)/opt/vyatta/etc/ips/
	cp -f pulledpork/pulledpork.conf $(DESTDIR)/opt/vyatta/etc/ips/
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	cd generated-templates; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)

