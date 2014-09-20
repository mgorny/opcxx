/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_COMMON_OBJECT_HXX
#define OPCUA_COMMON_OBJECT_HXX 1

#include <opcua/common/types.hxx>
#include <opcua/common/struct.hxx>

namespace opc_ua
{
	// (opaque)
	class Session;

	enum class AttributeId
	{
		NODE_ID = 1,
		NODE_CLASS = 2,
		BROWSE_NAME = 3,
		DISPLAY_NAME = 4,
		DESCRIPTION = 5,
		WRITE_MASK = 6,
		USER_WRITE_MASK = 7,
		EVENT_NOTIFIER = 12,
		VALUE = 13,
		DATA_TYPE = 14,
		VALUE_RANK = 15,
		ARRAY_DIMENSIONS = 16,
		ACCESS_LEVEL = 17,
		USER_ACCESS_LEVEL = 18,
		MINIMUM_SAMPLING_INTERVAL = 19,
		HISTORIZING = 20,
	};

	enum class NodeClass
	{
		UNSPECIFIED = 0,
		OBJECT = 1,
		VARIABLE = 2,
		METHOD = 4,
		OBJECT_TYPE = 8,
		VARIABLE_TYPE = 16,
		REFERENCE_TYPE = 32,
		DATA_TYPE = 64,
		VIEW = 128,
	};

	struct BaseNode
	{
		// variables
		virtual NodeId node_id() = 0;
		virtual NodeClass node_class() = 0;
		virtual QualifiedName browse_name() = 0;
		virtual LocalizedText display_name(Session& s, Double max_age) = 0;
		virtual LocalizedText description(Session& s, Double max_age);
		virtual UInt32 write_mask(Session& s, Double max_age) = 0;
		virtual UInt32 user_write_mask(Session& s, Double max_age) = 0;

		virtual Variant get_attribute(AttributeId a, Session& s, Double max_age);
		virtual StatusCode set_attribute(AttributeId a, Session& s, const Variant& new_value);
	};

	struct Variable : BaseNode
	{
		// variables
		virtual Variant value(Session& s, Double max_age) = 0;
		virtual NodeId data_type(Session& s, Double max_age) = 0;
		virtual Int32 value_rank(Session& s, Double max_age) = 0;
		virtual Array<UInt32> array_dimensions(Session& s, Double max_age) = 0;
		virtual Byte access_level(Session& s, Double max_age) = 0;
		virtual Byte user_access_level(Session& s, Double max_age) = 0;
		virtual Double minimum_sampling_interval(Session& s, Double max_age);
		virtual Boolean historizing(Session& s, Double max_age) = 0;

		// setters
		virtual StatusCode value(Session& s, const Variant& new_value) = 0;

		virtual Variant get_attribute(AttributeId a, Session& s, Double max_age);
		virtual StatusCode set_attribute(AttributeId a, Session& s, const Variant& new_value);
	};

	struct Object : BaseNode
	{
		// variables
		virtual Byte event_notifier(Session& s, Double max_age) = 0;

		virtual Variant get_attribute(AttributeId a, Session& s, Double max_age);
		virtual StatusCode set_attribute(AttributeId a, Session& s, const Variant& new_value);
	};
};

#endif /*OPCUA_COMMON_OBJECT_HXX*/
