rule SignKeywords
{
    meta:
        name = "SignKeywords"

    strings:
        $sign1 = /(\b|^|\s)(£|\$|€|¥|°\s?c|°\s?f|k)\s+\d+(\s|\b|$)/ nocase
        $sign2 = /\d+\s+(%|£|\$|€|¥|°\s?c|°\s?f|k)(\s|\b|$)/ nocase  
        $sign3 = /\d+\s+(k|h|d|c|m)?(g|l|oz|J|Wh)(c)?/ fullword nocase
        $sign4 = /(\b|^|\s)(k|h|d|c|m)?(g|l|oz|j|wh)(c)?\s+\d+(\s|\b|$)/ nocase

    condition:
        1 of them
}