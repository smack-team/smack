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

man_MANS = chsmack.8 smackaccess.1 smack_accesses_add.3 smackcipso.8 smackctl.8 smackd.8 smack_have_access.3 smackload.8
EXTRA_DIST += $(man_MANS)
