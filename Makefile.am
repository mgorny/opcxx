ACLOCAL_AMFLAGS = -I m4
AM_CXXFLAGS = \
	-std=c++11
AM_CPPFLAGS = \
	-I$(srcdir)/src

noinst_HEADERS = \
	src/opcua/common/struct.hxx \
	src/opcua/common/types.hxx \
	src/opcua/common/util.hxx \
	src/opcua/tcp/idmapping.hxx \
	src/opcua/tcp/streams.hxx \
	src/opcua/tcp/types.hxx

lib_LTLIBRARIES = libopcua.la
noinst_PROGRAMS = test

libopcua_la_SOURCES = \
	src/opcua/common/struct.cxx \
	src/opcua/common/types.cxx \
	src/opcua/common/util.cxx \
	src/opcua/tcp/idmapping.cxx \
	src/opcua/tcp/streams.cxx \
	src/opcua/tcp/types.cxx \
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

TESTS = tests/serializer
check_PROGRAMS = tests/serializer

tests_serializer_SOURCES = tests/serializer.cxx
tests_serializer_LDADD = libopcua.la

# Used to extract compile flags for YCM.
print-%:
	@echo $($*)
