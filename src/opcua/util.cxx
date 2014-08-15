/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "util.hxx"

#include <stdexcept>

opc_ua::SerializationContext::SerializationContext(evbuffer* buf)
	: _buf(buf)
{
}

size_t opc_ua::SerializationContext::size()
{
	return evbuffer_get_length(_buf);
}

void opc_ua::SerializationContext::read(void* data, size_t size)
{
	size_t rd = evbuffer_remove(_buf, data, size);

	if (rd < size)
		throw std::runtime_error("Failure draining the buffer");
}

void opc_ua::SerializationContext::write(const void* data, size_t size)
{
	if (evbuffer_add(_buf, data, size) == -1)
		throw std::runtime_error("Failure appending to buffer");
}

void opc_ua::SerializationContext::write(const SerializationContext& ctx)
{
	evbuffer_add_buffer(_buf, ctx._buf);
}

opc_ua::TemporarySerializationContext::TemporarySerializationContext()
	: SerializationContext(evbuffer_new())
{
	if (!_buf)
		throw std::runtime_error("Buffer allocation failed");
}

opc_ua::TemporarySerializationContext::~TemporarySerializationContext()
{
	evbuffer_free(_buf);
}
