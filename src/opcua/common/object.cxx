/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "object.hxx"

opc_ua::LocalizedText opc_ua::BaseNode::description(Session& s, Double max_age)
{
	return {"", ""};
}

opc_ua::Variant opc_ua::BaseNode::get_attribute(AttributeId a, Session& s, Double max_age)
{
	switch (a)
	{
		default:
			throw std::runtime_error("Unsupported attribute requested");
	}
}

opc_ua::StatusCode opc_ua::BaseNode::set_attribute(AttributeId a, Session& s, const Variant& new_value)
{
	switch (a)
	{
		default:
			throw std::runtime_error("Unsupported attribute requested");
	}
}

opc_ua::Double opc_ua::Variable::minimum_sampling_interval(Session& s, Double max_age)
{
	// indeterminate
	return -1;
}

opc_ua::Variant opc_ua::Variable::get_attribute(AttributeId a, Session& s, Double max_age)
{
	switch (a)
	{
		case AttributeId::VALUE:
			return value(s, max_age);
		default:
			return BaseNode::get_attribute(a, s, max_age);
	}
}

opc_ua::StatusCode opc_ua::Variable::set_attribute(AttributeId a, Session& s, const Variant& new_value)
{
	switch (a)
	{
		case AttributeId::VALUE:
			return value(s, new_value);
		default:
			return BaseNode::set_attribute(a, s, new_value);
	}
}

opc_ua::Variant opc_ua::Object::get_attribute(AttributeId a, Session& s, Double max_age)
{
	switch (a)
	{
		case AttributeId::EVENT_NOTIFIER:
			return event_notifier(s, max_age);
		default:
			return BaseNode::get_attribute(a, s, max_age);
	}
}

opc_ua::StatusCode opc_ua::Object::set_attribute(AttributeId a, Session& s, const Variant& new_value)
{
	switch (a)
	{
		default:
			return BaseNode::set_attribute(a, s, new_value);
	}
}
