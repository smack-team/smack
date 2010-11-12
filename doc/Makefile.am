EXTRA_DIST=Doxyfile

docpkg = $(PACKAGE_TARNAME)-doxygen-$(PACKAGE_VERSION).tar.gz

CLEANFILES = $(docpkg)

doc_DATA = $(docpkg)

$(docpkg): doxygen.stamp
if HAVE_DOXYGEN
	tar chof - html | gzip -9 -c >$@
endif

doxygen.stamp: Doxyfile
if HAVE_DOXYGEN
	$(DOXYGEN) $(DOXYFLAGS) $<
	echo Timestamp > $@
endif

clean-local:
if HAVE_DOXYGEN
	rm -rf html
endif
