packet_types = {
	[0] = "HELLO",
	[1] = "LINK_INFO",
	[2] = "ROUTE_REQUEST",
	[3] = "ROUTE",
	[4] = "NO_ROUTE",
	[5] = "INVALIDATE_ROUTES",
}
link_speeds = {
	[0] = "10Mbps",
	[1] = "100Mbps",
	[2] = "1Gbps",
	[3] = "10Gbps",
	[4] = "40Gbps",
	[5] = "100Gbps",
}

oof_proto = Proto("Oof", "Oof: OpenFlow")

f_packet_type = ProtoField.uint8("oof.type", "Packet type", base.DEC, packet_types)
f_link_count = ProtoField.uint16("oof.link_count", "Link count", base.DEC)
f_link_ip = ProtoField.ipv4("oof.link_ip", "IP address")
f_link_net_prefix = ProtoField.uint8("oof.link_net_preifx", "Network CIDR prefix", base.DEC)
f_link_speed = ProtoField.string("oof.link_speed", "Link speed", base.UNICODE)
f_destination = ProtoField.ipv4("oof.destination", "Destination IP address")
f_next_hop = ProtoField.ipv4("oof.next_hop", "Next hop")
oof_proto.fields = { f_packet_type, f_link_count, f_link_ip, f_link_net_prefix, f_link_speed, f_destination, f_next_hop }

function oof_length(buffer, offset)
	local msg_len = buffer:len() - offset
	if msg_len ~= buffer:reported_length_remaining(offset) then
		-- the packet is being cut off, no point in dissecting it
		return 0
	end

	local p_type = buffer(offset, 1):uint()
	if p_type == 5 then
		return 1, p_type
	end

	local real_len = 1
	if p_type == 0 then
		if msg_len < 4 then
			return -(4 - msg_len)
		end
		real_len = real_len + 3
	elseif p_type == 1 then
		if msg_len < 3 then
			return -DESEGMENT_ONE_MORE_SEGMENT
		end

		local link_count = buffer(offset + 1, 2):uint()
		local required_len = real_len + 2 + (link_count * 6)
		if msg_len < required_len then
			return -(required_len - msg_len)
		end
		real_len = required_len
	elseif p_type == 2 or p_type == 3 or p_type == 4 then
		if msg_len < 5 then
			return -(5 - msg_len)
		end
		real_len = real_len + 4
	else
		return 0, p_type
	end
	return real_len, p_type
end
function oof_dissect(buffer, pinfo, root, offset)
	local msg_len, p_type = oof_length(buffer, offset)
	if msg_len <= 0 then
		return msg_len
	end

	pinfo.cols.protocol:set("Oof")
	if string.find(tostring(pinfo.cols.info), "^Oof") == nil then
		pinfo.cols.info:set("Oof")
	end

	local tree = root:add(oof_proto, buffer(offset, msg_len), "Oof")
	if p_type == 0 and buffer(offset + 1, 3):string() ~= "Oof" then
		return 0
	end

	tree:add(f_packet_type, buffer(offset, 1))
	if p_type == 1 then
		local link_count_tvb = buffer(offset + 1, 2)
		tree:add(f_link_count, link_count_tvb)
		for i=0,link_count_tvb:uint()-1 do
			local offset = offset + 3 + (i*6)
			local ip_tvb = buffer(offset, 4)
			local prefix_tvb = buffer(offset + 4, 1)
			local speed_tvb = buffer(offset + 5, 1)

			local link_speed = "Unknown"
			if speed_tvb:uint() <= 5 then
				link_speed = link_speeds[speed_tvb:uint()]
			end
			local link_str = tostring(ip_tvb:ipv4()) .. "/" .. tostring(prefix_tvb:uint()) .. " @ " .. link_speed
			local link_item = tree:add(tree, buffer(offset, 6))
			link_item:set_text("Link: " .. link_str)
			link_item:add(f_link_ip, ip_tvb)
			link_item:add(f_link_net_prefix, prefix_tvb)

			link_item:add(f_link_speed, speed_tvb, link_speed)
		end
	elseif p_type == 2 or p_type == 4 then
		tree:add(f_destination, buffer(offset + 1), 4)
	elseif p_type == 3 then
		tree:add(f_next_hop, buffer(offset + 1), 4)
	end

	return msg_len
end
function oof_proto.dissector(buffer, pinfo, tree)
	local total_bytes = buffer:len()
	local bytes_consumed = 0
	while bytes_consumed < total_bytes do
		local result = oof_dissect(buffer, pinfo, tree, bytes_consumed)
		if result > 0 then
			bytes_consumed = bytes_consumed + result
		elseif result == 0 then
			return 0
		else
			pinfo.desegment_offset = bytes_consumed
			pinfo.desegment_len = -result
			return total_bytes
		end
	end

	return bytes_consumed
end

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(27999, oof_proto)
