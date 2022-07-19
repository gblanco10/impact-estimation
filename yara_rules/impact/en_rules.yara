include "generic_rules.yara"

rule NotDigitKeywords
{
    meta:
        name = "NotDigitKeywords"

    strings:
        $string1 = /(in|on|during|from|since)\s+\d+/ fullword nocase
        $string2 = /\d+\s+(year(s)?|time(s)?|month(s)?|day(s)?|week(s)?|hour(s)?|minute(s)?|second(s)?|am|pm|yr|old|st|th|nd|rd|degree(s)?|total)/ fullword nocase
        
        $string3 = /\d{1,2}\s+(of\s+)?(jan(uary)?|feb(ruary)?|mar(ch)?|apr(il)?|may|jun(e)?|jul(y)?|aug(ust)?|sep(tember)?|oct(ober)?|nov(ember)?|dec(ember)?)/ fullword nocase
        $string4 = /(jan(uary)?|feb(ruary)?|mar(ch)?|apr(il)?|may|jun(e)?|jul(y)?|aug(ust)?|sep(tember)?|oct(ober)?|nov(ember)?|dec(ember)?)\s+(the\s+)?\d{1,2}/ fullword nocase
        
        $string5 = /\d+\s+(of\s+)?(euro(s)?|dollar(s)?|pound(s)?|penny|pence|quintal(s)?|ton(s)?|yen(s)?|(swiss\s)?franc(s)?)/ fullword nocase
        $string6 = /(euro(s)?|dollar(s)?|pound(s)?|penny|pence|quintal(s)?|ton(s)?|yen(s)?|(swiss\s)?franc(s)?)\s+\d+/ fullword nocase
        
        $string7 = /\d+\s+(of\s+)?(in(ch(es)?)?|f(ee)?t(s)?|y(ar)?d(s)?|ounce(s)?|oz|mile(s)?)(\s?c|\s?q|2|\s?²)?/ fullword nocase
        $string8 = /(in(ch(es)?)?|f(ee)?t(s)?|y(ar)?d(s)?|ounce(s)?|oz|mile(s)?)(\s?c|\s?q|2|\s?²)?\s+\d+/ fullword nocase

        $string9 = /\d+\s+(of\s+)?((k(ilo)?|c(enti)?|d(eci)|m(illi)?|h(ecto)?)(-|\s)?)?(m(eter(s)?)?|metre(s)?|g(ram(s)?)?|l(it(er|res))?|j(oule(s)?)?|watt(-)?hour|wh)(\s?c|\s?q|2|\s?²)?/ fullword nocase
        $string10 = /((k(ilo)?|c(enti)?|d(eci)|m(illi)?|h(ecto)?)(-|\s)?)?(m(eter(s)?)?|metre(s)?|g(ram(s)?)?|l(it(er|res))?|j(oule(s)?)?|watt(-)?hour|wh)(\s?c|\s?q|2|\s?²)?\s+\d+/ fullword nocase

    condition:
        SignKeywords or (1 of ($string*))
}