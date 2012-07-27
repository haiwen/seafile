
#if COMPILE_HTTPSERVER
#  MAKE_HTTPSERVER = httpserver
#endif

if COMPILE_SERVER
  MAKE_SERVER = server tools monitor $(MAKE_HTTPSERVER) controller
endif

if COMPILE_CLIENT
  MAKE_CLIENT = daemon
endif

#SUBDIRS = include lib common daemon $(MAKE_CLINET) $(MAKE_SERVER) \
#	app python tests
SUBDIRS = include lib common daemon server
