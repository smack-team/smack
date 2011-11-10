EXTRA_DIST=Doxyfile

if ENABLE_DOXYGEN

docpkg = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)-doc.tar.gz

CLEANFILES = $(docpkg) doxygen.stamp

doc_DATA = $(docpkg)

$(docpkg): doxygen.stamp
	tar chof - html | gzip -9 -c >$@

doxygen.stamp: Doxyfile
	$(DOXYGEN)  $<
	echo Timestamp > $@

clean-local:
	rm -rf html

endif
