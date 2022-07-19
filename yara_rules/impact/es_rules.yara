include "generic_rules.yara"

rule NotDigitKeywords
{
    meta:
        name = "NotDigitKeywords"

    strings:
        $string1 = /(\b|^)(en|el|durante|hasta|las)\s+\d+/ nocase
        $string2 = /\d+\s+(año(s)?|mes(es)?|día(s)?|hora(s)?|semana(s)?|minuto(s)?|segundo(s)?|total|am|pm|grado(s)?|veces)(\b|$)/ nocase
        $string3 = /\d{1,2}\s+(de\s+)?(enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre)(\b|$)/ nocase
        $string4 = /\d+\s+(de\s+)?(euro(s)?|dólar(es)?|libra(s)?|yen(es)?|franco(s)?|tonelada(s)?|quintal(es)?)(\b|$)/ nocase
        
        $string5 = /\d+\s+(de\s+)?((chilo|kilo|k(iló)?|c(entí)?|centi|m(ili)?|d(eci)?|decí|milí|h(ectó)?)(-|\s)?)?(pies|in|mi(llas)?|g(ramo(s)?)?|l(itro(s)?)?|kilo(s)?|j(oule)?|wh|vatios(-)?hora)(\s?c(uadr(ad)?[oie](s)?)?|\s?²|2)?(\b|$)/ nocase
        $string6 = /\d+\s+(de\s+)?((chilo|kilo|k(iló)?|c(entí)?|centi|m(ili)?|d(eci)?|decí|milí|h(ectó)?)(-|\s)?)?m(etro(s)?)?(\s?c(uadr(ad)?[oie](s)?)?|\s?²|2)?(\b|$)/ nocase


    condition:
       SignKeywords or (1 of ($string*))
}