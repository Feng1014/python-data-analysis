-- @brief A simple post-dissector, just append string to info column
-- @author zzq
-- @date 2015.08.13
local json = require("dkjson")
local my_proto = Proto("Filter", "Custom Packet Filter")

local pf_match = ProtoField.uint8("myfilter.match", "Filter Match", base.DEC,
                                  nil, nil,
                                  "1 if packet matches filter, 0 otherwise")
my_proto.fields = {pf_match}

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
        local is_hex = false
        if sid and content then
            local has_hex = content:match("^|.-|$") -- 检测 |xx xx| 格式
            if has_hex then
                is_hex = true
                content = content:gsub("^|", ""):gsub("|$", ""):gsub(" ", "")
            end
            table.insert(rules, {sid = sid, content = content, is_hex = is_hex})
        end
    end
    file:close()
    return rules
end

-- the dissector function callback
function my_proto.dissector(tvb, pinfo, buffer)
    -- local file = io.open("C:\\Program Files\\Suricata\\log\\eve.json", "r")
    -- local event
    -- local pcap_cnt = 0
    -- local event_type
    -- local sid
    -- local signature
    -- local is_match = 0
    -- if file then
    --     for line in file:lines() do
    --         event = json.decode(line)
    --         pcap_cnt = event['pcap_cnt']
    --         event_type = event['event_type']
    --         if pinfo.number == pcap_cnt and event_type == 'alert' then
    --             sid = tonumber(event['alert']['signature_id'])
    --             signature = event['alert']['signature']
    --             pinfo.cols.info:append('   ---' .. sid .. '---' .. signature)
    --             is_match = 1
    --             -- print(string.format("Packet %d matches: Src IP=%s, Dst IP=%d", pinfo.number, pinfo.src, pinfo.dst))
    --         end
    --     end
    --     file:close()
    -- else
    --     print("close file failed")
    -- end
    -- -- Add match status to protocol tree
    -- local subtree = tree:add(my_proto, tvb(), "Custom Packet Filter")
    -- subtree:add(pf_match, is_match)

    -- 加载规则文件
    suricata_rules = load_suricata_rules(
                         "C:\\Program Files\\Suricata\\rules\\botcc1.rules")
    rules = json.encode(suricata_rules)
    for k, v in ipairs(rules) do 
        local is_hex = item.is_hex
        print("is_hex:", is_hex)
    print(rules)
    -- print(type(rules))
end
-- register our new dummy protocol for post-dissection
register_postdissector(my_proto)
