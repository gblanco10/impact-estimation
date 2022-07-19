include "generic_rules.yara"

rule NotDigitKeywords
{
    meta:
        name = "NotDigitKeywords"

    strings:
        $string1 = /(nel|il|durante|del|dal|al|alle)\s+\d+/ fullword nocase
        $string2 = /\d+\s+(ann[oi]|mes[ei]|giorn[oi]|enn[ei]|or[ae]|minut[oi]|second[oi]|settiman[ae]|totale|grad[oi]|volte)/ fullword nocase
        $string3 = /\d{1,2}\s+(di\s+)?(gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|novembre|dicembre)/ fullword nocase
        $string4 = /\d+\s+(di\s+)?(euro|dollar[oi]|sterlin[ae]|yen|franc(o|hi)|tonnellat[ae]|quintal[ei])/ fullword nocase
        
        $string5 = /\d+\s+(di\s+)?(chilo|k(ilo)?|c(enti)?|d(eci)?|m(illi)?|etto|h)?(-|\s)?(m(etr[oi])?|ft|iard[ae]|pied[ei]|mi(gli[oa])?)(\s?q(uadr(at)?[oie])?|²|2)?/ fullword nocase
        $string6 = /\d+\s+(di\s+)?((chilo|k(ilo)?|c(enti)?|d(eci)?|m(illi)?|h|etto)(-|\s)?)?(g(ramm[oi])?|l(itr[oi])?|j(oule)?|wh|wattora|chili)/ fullword nocase

    condition:
        SignKeywords or (1 of ($string*))
}