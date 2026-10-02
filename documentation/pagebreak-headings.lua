local PAGE_BREAK_XML = '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'

local function page_break()
  return pandoc.RawBlock("openxml", PAGE_BREAK_XML)
end

local function is_page_break(block)
  return block and block.t == "RawBlock" and block.format == "openxml" and block.text == PAGE_BREAK_XML
end

local function append_page_break(blocks)
  if not is_page_break(blocks[#blocks]) then
    table.insert(blocks, page_break())
  end
end

function Pandoc(doc)
  local output = pandoc.List()

  for _, block in ipairs(doc.blocks) do
    local top_level_header = block.t == "Header" and block.level <= 2
    if top_level_header and #output > 0 then
      append_page_break(output)
    end

    table.insert(output, block)
  end

  doc.blocks = output
  return doc
end

function Image(image)
  if image.src:match("diagram_02") then
    image.attributes.width = "3.06in"
  else
    image.attributes.width = "4.67in"
  end
  return image
end
