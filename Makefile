NAME=ketones

prefix=/usr
includedir=${prefix}/include
libdir=${prefix}/lib
libdevdir=${prefix}/lib
mandir=${prefix}/man
datadir=${prefix}/share
bindir=${prefix}/bin

default: all

all:
	@$(MAKE) -C src

.PHONY: all install default clean
.PHONY: FORCE

clean:
	@$(MAKE) -C src clean

install:
	@$(MAKE) -C src install prefix=$(DESTDIR)$(prefix) \
		includedir=$(DESTDIR)$(includedir) \
		libdir=$(DESTDIR)$(libdir) \
		libdevdir=$(DESTDIR)$(libdevdir) \
		bindir=$(DESTDIR)$(bindir)
