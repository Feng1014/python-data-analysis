-- 定义协议名称（自定义）
local proto_name = "PacketInfoExtractor"

-- 创建协议对象
local my_proto = Proto(proto_name, "Packet Information Extractor")

-- 定义字段（用于显示在 Wireshark 的协议树中）
local pf_packet_info = ProtoField.string("packetinfo.info", "Packet Information")
local pf_hex_data = ProtoField.string("packetinfo.hex", "Hex Data")
local pf_string_data = ProtoField.string("packetinfo.string", "String Data")

-- 注册字段
my_proto.fields = { pf_packet_info, pf_hex_data, pf_string_data }

-- 定义输出文件（可选）
local output_file = io.open("C:\\Users\\cykj\\Downloads\\code\\packet_info.txt", "w")

-- 解析器函数
function my_proto.dissector(tvb, pinfo, tree)
    -- 添加协议树节点
    local subtree = tree:add(my_proto, tvb(), "Packet Information Extractor")

    -- 获取数据包的基本信息
    local packet_number = tostring(pinfo.number)
    local timestamp = tostring(pinfo.abs_ts) -- 时间戳
    local src_addr = tostring(pinfo.src)
    local src_port = tostring(pinfo.src_port)
    local dst_addr = tostring(pinfo.dst)
    local dst_port = tostring(pinfo.dst_port)
    local protocol = tostring(pinfo.cols.protocol)
    local len = tostring(pinfo.len)
    local info = tostring(pinfo.cols.info)

    -- 组合分组信息
    local packet_info = string.format(
        "[Packet: %s, Timestamp: %s, Source: %s, Source_port: %s, Destination: %s, Destination_port: %s, Protocol: %s, Length: %s, Info: %s]",
        packet_number, timestamp, src_addr, src_port, dst_addr, dst_port, protocol, len, info
    )

    -- 添加分组信息到协议树
    subtree:add(pf_packet_info, tvb(), packet_info)

    -- 获取数据包的原始数据
    local packet_data = tvb:raw(0, tvb:len())

    -- 转换为十六进制格式
    local hex_data = ""
    for i = 1, #packet_data do
        hex_data = hex_data .. string.format("%02X ", string.byte(packet_data, i))
    end

    -- 添加十六进制数据到协议树
    subtree:add(pf_hex_data, tvb(), hex_data)

    -- 转换为可打印字符串（不可打印字符用 . 代替）
    local string_data = ""
    for i = 1, #packet_data do
        local byte = string.byte(packet_data, i)
        if byte >= 32 and byte <= 126 then
            string_data = string_data .. string.char(byte)
        else
            string_data = string_data .. "."
        end
    end

    -- 添加字符串数据到协议树
    subtree:add(pf_string_data, tvb(), string_data)

    -- 输出到控制台
    print("=== Packet Info ===")
    print(packet_info)
    print("Hex Data: " .. hex_data)
    print("String Data: " .. string_data)
    print("==================")

    -- 输出到文件（可选）
    if output_file then
        output_file:write("=== Packet Info ===\n")
        output_file:write(packet_info .. "\n")
        output_file:write("Hex Data: " .. hex_data .. "\n")
        output_file:write("String Data: " .. string_data .. "\n")
        output_file:write("==================\n")
        output_file:flush()
    end
end

-- 注册解析器到 Wireshark
register_postdissector(my_proto)

-- 脚本卸载时关闭文件（如果使用了文件输出）
-- function my_proto.init()
--     if output_file then
--         output_file:close()
--         output_file = nil
--     end
-- end