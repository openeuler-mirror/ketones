NAME=ketones
TOP := $(dir $(CURDIR)/$(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)))
SPECFILE=$(TOP)/$(NAME).spec
VERSION=$(shell awk '/Version:/ { print $$2 }' $(SPECFILE))
VERSION_MAJOR=$(shell echo $(VERSION) | cut -d. -f1)
VERSION_MINOR=$(shell echo $(VERSION) | cut -d. -f2)
RELEASE=$(shell awk '/Release:/ { print $$2 }' $(SPECFILE) | awk '{gsub(/%{.*}/, ""); print}')
TAG = $(NAME)-$(VERSION)-$(RELEASE)
RPMBUILD=$(shell `which rpmbuild >&/dev/null` && echo "rpmbuild" || echo "rpm")

prefix=/usr
includedir=${prefix}/include
libdir=${prefix}/lib
libdevdir=${prefix}/lib
mandir=${prefix}/man
datadir=${prefix}/share
bindir=${prefix}/bin

.PHONY: all install default clean
.PHONY: FORCE

default: all

MAKEFLAGS += --no-print-directory

all:
	@$(MAKE) -C src

clean:
	@$(MAKE) -C src clean

install:
	@$(MAKE) -C src install prefix=$(DESTDIR)$(prefix) \
		includedir=$(DESTDIR)$(includedir) \
		libdir=$(DESTDIR)$(libdir) \
		libdevdir=$(DESTDIR)$(libdevdir) \
		bindir=$(DESTDIR)$(bindir)

create-archive:
	@git archive --prefix=$(NAME)-$(VERSION)/ -o $(NAME)-$(VERSION).tar.gz $(TAG)
	@echo "The final archive is ./$(NAME)-$(VERSION).tar.gz."

srpm: create-archive
	$(RPMBUILD) --define "_sourcedir `pwd`" --define "_srcrpmdir `pwd`" --nodeps -bs $(SPECFILE)
