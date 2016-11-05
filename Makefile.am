SUBDIRS                   = src man scripts www
dist_sysconf_DATA         = merecat.conf
doc_DATA                  = README.md LICENSE
EXTRA_DIST                = README.md README.thttpd LICENSE
DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd)

if HAVE_SYSTEMD
systemd_DATA              = merecat.service
endif

# Target to run when building a release
release: dist
	@for file in $(DIST_ARCHIVES); do	\
		md5sum $$file > ../$$file.md5;	\
	done
	@mv $(DIST_ARCHIVES) ../
	@echo
	@echo "Resulting release files:"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do					\
		printf "$$file    \tDistribution tarball\n";			\
		printf "$$file.md5\t"; cat ../$$file.md5 | cut -f1 -d' ';	\
	done
