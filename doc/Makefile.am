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

man_MANS = smackaccess.1 \
	   smack_accesses_add.3 \
	   smack_accesses_add_from_file.3 \
	   smack_accesses_apply.3 \
	   smack_accesses_clear.3 \
	   smack_accesses_free.3 \
	   smack_accesses_new.3 \
	   smack_accesses_save.3 \
	   smack_have_access.3 \
	   smack_new_label_from_self.3 \
	   smack_new_label_from_socket.3 \
	   smack_set_label_for_self.3 \
	   smack_revoke_subject.3 \
	   smack_fgetlabel.3 \
	   smack_fsetlabel.3 \
	   smack_getlabel.3 \
	   smack_lgetlabel.3 \
	   smack_lsetlabel.3 \
	   smack_setlabel.3 \
	   chsmack.8 \
	   smackcipso.8 \
	   smackctl.8 \
	   smackd.8 \
	   smackload.8

EXTRA_DIST += $(man_MANS)
