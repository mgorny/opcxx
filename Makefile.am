ACLOCAL_AMFLAGS = -I m4
AM_CXXFLAGS = \
	-std=c++11 -Wswitch-enum
AM_CPPFLAGS = \
	-I$(srcdir)/src

noinst_HEADERS = \
	src/opcua/common/object.hxx \
	src/opcua/common/struct.hxx \
	src/opcua/common/types.hxx \
	src/opcua/common/util.hxx \
	src/opcua/tcp/idmapping.hxx \
	src/opcua/tcp/server.hxx \
	src/opcua/tcp/streams.hxx \
	src/opcua/tcp/types.hxx \
	src/mt101/mt101.hxx

lib_LTLIBRARIES = libopcua.la libmt101.la
noinst_PROGRAMS = client mt101-server virtual-server

libopcua_la_SOURCES = \
	src/opcua/common/object.cxx \
	src/opcua/common/struct.cxx \
	src/opcua/common/types.cxx \
	src/opcua/common/util.cxx \
	src/opcua/tcp/idmapping.cxx \
	src/opcua/tcp/server.cxx \
	src/opcua/tcp/streams.cxx \
	src/opcua/tcp/types.cxx \
	$(noinst_HEADERS)
libopcua_la_CPPFLAGS = \
	$(LIBEVENT_CFLAGS) \
	$(AM_CPPFLAGS)
libopcua_la_LIBADD = \
	$(LIBEVENT_LIBS)

libmt101_la_SOURCES = \
	src/mt101/mt101.cxx \
	$(noinst_HEADERS)
libmt101_la_CPPFLAGS = \
	$(LIBMODBUS_CFLAGS) \
	$(AM_CPPFLAGS)
libmt101_la_LIBADD = \
	$(LIBMODBUS_LIBS)

client_CPPFLAGS = \
	$(libopcua_la_CPPFLAGS) \
	$(AM_CPPFLAGS)
client_LDADD = \
	libopcua.la
client_SOURCES = \
	src/cli/client.cxx \
	$(noinst_HEADERS)

mt101_server_CPPFLAGS = \
	$(libopcua_la_CPPFLAGS) \
	$(libmt101_la_CPPFLAGS) \
	$(AM_CPPFLAGS)
mt101_server_LDADD = \
	libmt101.la \
	libopcua.la
mt101_server_SOURCES = \
	src/cli/mt101-server.cxx \
	$(noinst_HEADERS)

virtual_server_CPPFLAGS = \
	$(libopcua_la_CPPFLAGS) \
	$(NCURSES_CFLAGS) \
	$(AM_CPPFLAGS)
virtual_server_LDADD = \
	libopcua.la \
	$(NCURSES_LIBS)
virtual_server_SOURCES = \
	src/cli/virtual-server.cxx \
	$(noinst_HEADERS)

TESTS = tests/serializer
check_PROGRAMS = tests/serializer

tests_serializer_SOURCES = tests/serializer.cxx
tests_serializer_LDADD = libopcua.la

# Used to extract compile flags for YCM.
print-%:
	@echo $($*)
