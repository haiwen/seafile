SUBDIRS = cdc index

proc_headers =
	$(addprefix processors/, \
	objecttx-common.h \
	putblock-proc.h \
	blocktx-common.h \
	blocktx-common-impl.h)

noinst_HEADERS = \
	unpack-trees.h \
	seaf-tree-walk.h \
	diff-simple.h \
	seafile-crypt.h \
	common.h \
	bitfield.h \
	branch-mgr.h \
	fs-mgr.h \
	block-mgr.h \
	commit-mgr.h \
	info-mgr.h \
	log.h \
	avl/avl.h \
	object-list.h \
	vc-common.h \
	seaf-utils.h \
	obj-store.h \
	obj-backend.h \
	riak-client.h \
	block-backend.h \
	block.h \
	mq-mgr.h \
	seaf-db.h \
	merge-new.h \
	block-tx-utils.h \
	$(proc_headers)

#check_PROGRAMS = riak-http-test

#riak_http_test_SOURCES = riak-http-test.c riak-http-client.c

#riak_http_test_CPPFLAGS = -DRIAK_TEST
#riak_http_test_CFLAGS = @GLIB2_CFLAGS@ -I$(top_srcdir)/lib
#riak_http_test_LDADD = @GLIB2_LIBS@ -lcurl
