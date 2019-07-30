SUBDIRS                   = src www man scripts tests
doc_DATA                  = README.md LICENSE ChangeLog.md
EXTRA_DIST                = README.md LICENSE ChangeLog.md throttle.conf merecat.conf
DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd)

if HAVE_CONFUSE
dist_sysconf_DATA         = merecat.conf
endif

if HAVE_SYSTEMD
systemd_DATA              = merecat.service
endif

## Update html versions of man pages
doc:
	@for file in htpasswd.1 merecat.8 redirect.8 ssi.8; do		\
		out=www/$$file.html; 					\
		sed "s/%TITLE%/$$file/"	< www/header.html > $$out;	\
		mandoc -T html -O fragment -O man=%N.%S.html		\
			man/$$file >> $$out;				\
		cat www/footer.html >> $$out;				\
	done

## Generate .deb package
package:
	@dpkg-buildpackage -uc -us -B

## Generate MD5 checksum file
MD5 = md5sum
md5-dist:
	@for file in $(DIST_ARCHIVES); do	\
		$(MD5) $$file > ../$$file.md5;	\
		mv $$file ../;			\
	done

## Check if tagged in git
release-hook:
	if [ ! `git tag | grep $(PACKAGE_VERSION)` ]; then				\
		echo;									\
		printf "\e[1m\e[41mCannot find release tag $(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[5mDo release anyway?\e[0m "; read yorn;			\
		if [ "$$yorn" != "y" -a "$$yorn" != "Y" ]; then				\
			printf "OK, aborting release.\n";				\
			exit 1;								\
		fi;									\
		echo;									\
	else										\
		echo;									\
		printf "\e[1m\e[42mFound GIT release tag $(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[44m>>Remember to push tags!\e[0m\n";			\
		echo;									\
	fi

# Target to run when building a release
release: distcheck release-hook md5-dist
	@echo
	@echo "Resulting release files:"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do					\
		printf "$$file    \tDistribution tarball\n";			\
		printf "$$file.md5\t"; cat ../$$file.md5 | cut -f1 -d' ';	\
	done
