-- 定义协议名称
local proto_name = "SuricataMatcher"

-- 创建协议对象
local my_proto = Proto(proto_name, "Suricata-Message")

-- 定义协议字段
local pf_packet_info = ProtoField.string("suricata.packet_info",
                                         "Packet Information")
local pf_hex_data = ProtoField.string("suricata.hex_data", "Hex Data")
local pf_string_data = ProtoField.string("suricata.string_data", "String Data")
local pf_match_result = ProtoField.string("suricata.match",
                                          "Suricata Rule Match Result")

-- 注册协议字段
my_proto.fields = {pf_packet_info, pf_hex_data, pf_string_data, pf_match_result}

-- 示例 Suricata 规则（可替换为文件或用户输入）
-- 格式：{ sid = 规则ID, content = 匹配内容, is_hex = 是否为十六进制 }
local suricata_rules = {
    {sid = "10001", content = "SMBu", is_hex = false},
    {sid = "10002", content = "01680f2001bdfd33a42dd27b8f365018", is_hex = true}, -- 十六进制示例：ABCD
    {sid = "10003", content = "01680f2001bdfd33a985d27b94c55011", is_hex = true}
}

-- local suricata_rules_path = "C:\\Program Files\\Suricata\\rules\\botcc.rules"

-- 输出文件（可选）
local output_file = io.open(
                        "C:\\Users\\cykj\\Downloads\\code\\suricata_match.txt",
                        "w")

-- 辅助函数：将十六进制字符串转换为字节
local function hex_to_bytes(hex_str)
    hex_str = hex_str:gsub("%s", "") -- 移除空格
    local bytes = ""
    for i = 1, #hex_str, 2 do
        local hex_pair = hex_str:sub(i, i + 1)
        bytes = bytes .. string.char(tonumber(hex_pair, 16))
    end
    return bytes
end

-- 从文件加载 Suricata 规则
local function load_suricata_rules(filename)
    local rules = {}
    local file = io.open(filename, "r")
    if not file then
        print("Error: Cannot open rules file " .. filename)
        return rules
    end

    for line in file:lines() do
        -- 简单解析规则（仅提取 sid 和 content）
        local sid = line:match('sid:(%d+);')
        local content = line:match('content:"(.-)";')
        if sid and content then
            local is_hex = content:match("^|.-|$") -- 检测 |xx xx| 格式
            if is_hex then
                content = content:gsub("^|", ""):gsub("|$", ""):gsub(" ", "")
            end
            table.insert(rules, {sid = sid, content = content, is_hex = is_hex})
        end
    end
    file:close()
    return rules
end

-- 解析器函数
function my_proto.dissector(tvb, pinfo, tree)
    -- 添加协议树节点
    local subtree = tree:add(my_proto, tvb(), "Suricata Rule Matcher")

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
                            packet_number, timestamp, src_addr, src_port,
                            dst_addr, dst_port, protocol, len, info)

    -- 添加分组信息到协议树
    subtree:add(pf_packet_info, tvb(), packet_info)

    -- 获取数据包原始数据
    local packet_data = tvb:raw(0, tvb:len())

    -- 转换为十六进制格式
    local hex_data = ""
    for i = 1, #packet_data do
        hex_data = hex_data ..
                       string.format("%02X ", string.byte(packet_data, i))
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

    -- 加载规则文件
    -- suricata_rules = load_suricata_rules(suricata_rules_path)

    -- Suricata 规则匹配
    local match_results = {}
    for _, rule in ipairs(suricata_rules) do
        local match_found = false
        local content = rule.content

        if rule.is_hex then
            -- 十六进制规则：将规则内容转换为字节
            content = hex_to_bytes(content)
            -- 在原始数据中查找
            if packet_data:find(content, 1, true) then
                match_found = true
            end
        else
            -- 字符串规则：直接在字符串数据中查找
            if packet_data:find(content, 1, true) then
                match_found = true
            end
        end

        if match_found then
            table.insert(match_results, string.format("SID: %s, Content: %s",
                                                      rule.sid, rule.content))
        end
    end

    -- 添加匹配结果到协议树
    local match_result_str = #match_results > 0 and
                                 table.concat(match_results, "; ") or
                                 "No match found"
    subtree:add(pf_match_result, tvb(), match_result_str)

    -- 输出到控制台
    print("=== Packet Info ===")
    print(packet_info)
    print("Hex Data: " .. hex_data)
    print("String Data: " .. string_data)
    print("Suricata Match: " .. match_result_str)
    print("==================")

    -- 输出到文件（可选）
    if output_file then
        output_file:write("=== Packet Info ===\n")
        output_file:write(packet_info .. "\n")
        output_file:write("Hex Data: " .. hex_data .. "\n")
        output_file:write("String Data: " .. string_data .. "\n")
        output_file:write("Suricata Match: " .. match_result_str .. "\n")
        output_file:write("==================\n")
        output_file:flush()
    end
end

-- 注册解析器到 Wireshark
register_postdissector(my_proto)

-- 脚本卸载时关闭文件
-- function my_proto.init()
--     if output_file then
--         output_file:close()
--         output_file = nil
--     end
-- end
