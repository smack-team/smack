EXTRA_DIST=Doxyfile

if HAVE_DOXYGEN

docpkg = $(PACKAGE_TARNAME)-doxygen-$(PACKAGE_VERSION).tar.gz

CLEANFILES = $(docpkg)

doc_DATA = $(docpkg)

$(docpkg): doxygen.stamp
	tar chof - html | gzip -9 -c >$@

doxygen.stamp: Doxyfile
	$(DOXYGEN) $(DOXYFLAGS) $<
	echo Timestamp > $@

clean-local:
	rm -rf html

endif
