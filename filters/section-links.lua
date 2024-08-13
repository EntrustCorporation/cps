-- Table to hold section references to identifiers
local section_refs = {}

-- Index headers
function Header(elem)
    local stringifiedHeader = pandoc.utils.stringify(elem)
    local identifier = elem.identifier
    local match = stringifiedHeader:match("^[%d%.]+")
    if match then
        local section_ref = "§" .. string.gsub(match, "%.$", "")
        section_refs[section_ref] = identifier
    end
end

-- Process text for section references
function Str(elem)
    local section_ref = elem.text:match("§[%d%.]+")
    
    if section_ref then
        local section_id = string.gsub(section_ref, "%.$", "")
        if section_refs[section_id] then
            local url = "#" .. section_refs[section_id]
            return pandoc.Link(section_ref, url)
        else
            io.stdout:write("::error::Unable to resolve section " .. section_ref .. "\n")
        end
    end
    return elem
end

-- Apply the filter
return {
    {Header = Header},
    {Str = Str}
}
