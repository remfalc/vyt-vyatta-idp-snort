cfgdir		 = $(datadir)/vyatta-cfg/templates
opdir		 = $(datadir)/vyatta-op/templates
share_perl5dir	 = $(datarootdir)/perl5/Vyatta/Snort
cron_hourlydir = /etc/cron.hourly

sbin_SCRIPTS = scripts/vyatta-update-snort.pl
sbin_SCRIPTS += scripts/vyatta-proc-snort-rules.pl
sbin_SCRIPTS += scripts/vyatta-update-inspection.pl
sbin_SCRIPTS += scripts/vyatta-show-ips.pl
sbin_SCRIPTS += scripts/vyatta-proc-snort-updates
sbin_SCRIPTS += scripts/vyatta-get-snort-rules.pl

share_perl5_DATA = lib/Vyatta/Snort/Config.pm
share_perl5_DATA += lib/Vyatta/Snort/UnifiedLog.pm

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)

