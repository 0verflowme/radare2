FILES=nes bf stm8
OPDIR=${DESTDIR}/$(DATADIR)/radare2/${VERSION}/platform

include ../../../config-user.mk

all:

clean:

.PHONY: all clean install install-symlink symstall uninstall

install:
	mkdir -p "${OPDIR}"
	# Remove the destination first. `make symstall` leaves each of these as a
	# symlink into this very directory, so a later `make install` asks cp to
	# copy a file onto itself; BSD cp calls that an error, install exits
	# non-zero, and everything after it in the install -- including the
	# libraries -- is silently skipped.
	for f in *.r2 ; do rm -f "${OPDIR}/$$f" ; cp -f "$$f" "${OPDIR}" ; done

# that sed is a workaround for mingw's pwd
CWD=$(shell pwd)
symstall install-symlink: ${F_SDB}
	mkdir -p "${OPDIR}"
	for a in ${FILES} ; do \
		ln -fs "${CWD}/$$a-init.r2" "${OPDIR}/$$a-init.r2" ; \
		ln -fs "${CWD}/$$a-fini.r2" "${OPDIR}/$$a-fini.r2" ; \
	done

uninstall:
	rm -rf "${OPDIR}"
