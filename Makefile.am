ACLOCAL_AMFLAGS = -I m4
AM_CXXFLAGS = \
	-std=c++11
AM_CPPFLAGS = \
	-I$(srcdir)/src

noinst_HEADERS = \
	src/opcua/ids.hxx \
	src/opcua/struct.hxx \
	src/opcua/tcp.hxx \
	src/opcua/types.hxx \
	src/opcua/util.hxx

lib_LTLIBRARIES = libopcua.la
noinst_PROGRAMS = test

libopcua_la_SOURCES = \
	src/opcua/struct.cxx \
	src/opcua/tcp.cxx \
	src/opcua/types.cxx \
	src/opcua/util.cxx \
	$(noinst_HEADERS)
libopcua_la_CPPFLAGS = \
	$(LIBEVENT_CFLAGS) \
	$(AM_CPPFLAGS)
libopcua_la_LIBADD = \
	$(LIBEVENT_LIBS)

test_CPPFLAGS = \
	$(libopcua_la_CPPFLAGS) \
	$(AM_CPPFLAGS)
test_LDADD = \
	libopcua.la
test_SOURCES = \
	test.cxx \
	$(noinst_HEADERS)

# Used to extract compile flags for YCM.
print-%:
	@echo $($*)
