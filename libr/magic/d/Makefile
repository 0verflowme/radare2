include ../../config.mk

MAGICDIR=${DESTDIR}${DATADIR}/radare2/${VERSION}/magic

all: $(F_SDB)

install: ${F_SDB}
	mkdir -p "$(MAGICDIR)"
	# The readlink guard covers MAGICDIR itself being a symlink, not the files
	# inside it. `make symstall` symlinks each file into this source tree, so
	# after one the cp below copies a file onto itself, which BSD cp reports as
	# an error and which then aborts the whole install.
	for a in default/* ; do readlink "$(MAGICDIR)";  if [ $$? != 0 ]; then rm -f "${MAGICDIR}/$$(basename $$a)" ; cp -f $$a "${MAGICDIR}" ; fi ; done

CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "$(MAGICDIR)"
	for FILE in $(shell cd default && ls) ; do \
		ln -fs "${CWD}/default/$$FILE" "$(MAGICDIR)/$$FILE" ; \
	done

.PHONY: install symstall
