EXTRA_DIST=Doxyfile

man_MANS = \
	smackaccess.1 \
	chsmack.8 \
	smackcipso.8 \
	smackload.8 \
	smackctl.8

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
	rm -rf man
	rm -f doxygen_sqlite3.db

EXTRA_MANS = \
	man/man3/SMACK_LABEL_LEN.3 \
	man/man3/smack.h.3 \
	man/man3/smack_accesses_add.3 \
	man/man3/smack_accesses_add_from_file.3 \
	man/man3/smack_accesses_add_modify.3 \
	man/man3/smack_accesses_apply.3 \
	man/man3/smack_accesses_clear.3 \
	man/man3/smack_accesses_free.3 \
	man/man3/smack_accesses_new.3 \
	man/man3/smack_accesses_save.3 \
	man/man3/smack_cipso_add_from_file.3 \
	man/man3/smack_cipso_apply.3 \
	man/man3/smack_cipso_free.3 \
	man/man3/smack_cipso_new.3 \
	man/man3/smack_have_access.3 \
	man/man3/smack_label_length.3 \
	man/man3/smack_new_label_from_path.3 \
	man/man3/smack_new_label_from_self.3 \
	man/man3/smack_new_label_from_socket.3 \
	man/man3/smack_revoke_subject.3 \
	man/man3/smack_set_label_for_self.3 \
	man/man3/smack_smackfs_path.3

$(EXTRA_MANS): doxygen.stamp
man_MANS += $(EXTRA_MANS)

endif

EXTRA_DIST += $(man_MANS)
