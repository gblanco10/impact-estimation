rule DamageImpact : Italian
{
meta:
    name = "damage"
	description = "Rule to detect if text is related to some damage "

strings:
    $word1 = /(fran[ae]|franament[oi]|franò|frana(t[aioe]|ndo|va(no)?|(ro)?no)?)/fullword
    $word2 = /(croll[aio]|crollat[aeio]|crollò|crolla(t[aioe]|ndo|va(no)?|(ro)?no)?)/ fullword
    $word3 = /chius(e(ro)?|[aioe]|ur([ae]))|bloccò|blocca(t[aioe]|ndo|va(no)?|(ro)?no)?|chiud(endo|eva(no)?|ono|e)/ fullword
    $word4 = /(cadut[aioe]|cad(de(ro)?|endo|eva(no)?|ono|e))/ fullword
    $word5 = /interr(uppe(ro)?|ott[aioe]|uzion([ei]))|interromp(endo|eva(no)?|ono|e)/ fullword
    $word6 = /distru(usse(ro)?|tt[aeio]|zion([ei])|ggendo|ggeva(no)?|gge)/ fullword
    $word7 = /(cediment[oi]|ced(ette(ro)?|endo|eva(no)?|ono|e)|cedut[aeio])/ fullword
    $word8 = /dann([io]|eggiament[oi])|danneggiò|danneggia(t[aioe]|ndo|va(no)?|(ro)?no)?/ fullword
    $word9 = /rott(ur[ae]|[aeio])|ruppe(ro)?|romp(endo|eva(no)?|ono|e)/ fullword
    $word10 = /(rovin[ae]|rovina(t[aioe]|ndo|va(no)?|(ro)?no)?)/ fullword
    $word11 = /smantellò|smantella(t[aeio]|ment([oi])|va(no)?|(ro)?no)/ fullword
    $word12 = /guast[aeoi]|guasta(t[aioe]|ndo|va(no)?|(ro)?no)?/ fullword
    $word13 = /sfaldament[oi]|sfaldò|sfalda(t[aioe]|ndo|va(no)?|(ro)?no)?/ fullword
    $word14 = /smottament[oi]/ fullword
    $word15 = /deteriorò|deteriora(t[aioe]|ment([oi])|ndo|va(no)?|(ro)?no)?/ fullword
    $word16 = /demol(ì|it[aioe]|izion([ei])|endo|iva(no)?|irono|isce|iscono)/ fullword
    $word17 = /abbatt(é|ette|erono|ut[aioe]|iment([oi])|endo|eva(no)?|ono|e)/ fullword
    $word18 = /incendi(ò|o)?|incendia(t[aioe]|ndo|va(no)?|(ro)?no)?|rog(o|hi)|fiamm[ae]/ fullword
    $word19 = /alluvion[ei]|inondò|inonda(zion[ei]|t[aioe]|ndo|va(no)?|(ro)?no)?|allagò|allaga(t[aioe]|ndo|va(no)?|(ro)?no)?|sommer(s[aioe]|sero|gendo|geva(no)?|gono|ge)/ fullword
    $word20 = /colp(ì|irono|it[aioe]|endo|iva(no)?|iscono)|centrò|centra(t[aioe]|ndo|va(no)?|(ro)?no)?/ fullword
    $word21 = /invest(ì|irono|it[aioe]|endo|iva(no)?|ono|e)|coinvol(se(ro)?|t[aioe]|gendo|geva(no)?|gono|ge)/ fullword
    $word22 = /devastò|devasta((ro)?no|t[aeio]|va(no)?)?|dilaniò|dilania(t[aioe]|ndo|va(no)?|(ro)?no)?/ fullword
    $word23 = /valang(a|he)|tempest[ae]|ciclon[ei]|uragan[oi]|bufer[ae]|temporal[ei]|tornado|torment[ae]|burrasc(a|he)|grandinat[ae]|piogg(ia|e)|acquazzon[ei]/ fullword
    $word24 = /bruciò|brucia(t[aioe]|ndo|va(no)?|(ro)?no)?|incener(ì|irono|it[aioe]|endo|iva(no)?|iscono|isce)/ fullword
    $word25 = /esplo(se(ro)?|sion[ei]|s[aioe]|dendo|deva(no)?|dono|de)/ fullword
    $word27 = /annientò|annienta(t[aioe]|ndo|va(no)?|(ro)?no)?/ fullword
    $word28 = /frantumò|frantuma(t[aioe]|ndo|va(no)?|(ro)?no)?|sfasciò|sfascia(t[aioe]|ndo|va(no)?|(ro)?no)?/ fullword
    $word29 = /sfondò|sfonda(t[aioe]|ndo|va(no)?|(ro)?no)?/ fullword
    $word30 = /malfunzionò|malfunziona(ment[aioe]|ndo|va(no)?|(ro)?no)?/ fullword
    $word31 = /incident[ei]|disastr[oi]/ fullword
    $word32 = /scoppia(t[aioe]|ndo|va(no)?|(ro)?no)?|scoppi(o|ò)?/ fullword
    $word33 = /terremot[oi]|sism[ai]|scosson[ei]/ fullword

    $word40 = /(senza|priv[aieo] di) acqua/ fullword
    $word41 = /(senza|priv[aieo] di) (energia elettrica|elettricità|corrente)/ fullword
condition:
	1 of them
}

rule Co2EmissionImpact: Max
{
    meta:
        name = "emission"
        decription = "Rule to detect if text is related to co2 emission"
    strings:
        $word10 = /co2|carbonio|anidride carbonica|(d|b)iossido di carbonio|co²/ fullword
        
        $word20 = /emission[ei]|emett(e(ndo)?|ono|eva(no)?)|emise(ro)?|emesso/ fullword

        $word30 = /tonnellat[ae]|quintal[ei]|k(ilo)?g(ramm[oi])?|chil[oi]/ fullword
    condition:
        (1 of ($word1*)) and (1 of ($word2*)) and (1 of ($word3*)) 

}

rule BurnedAreaImpact: Max
{
    meta:
        name = "area"
	    description = "Rule to detect if text is related to some burned area "
    strings:
        $word10 = /incendi(ò|o)?|incendia(t[aioe]|ndo|va(no)?|(ro)?no)?|rog(o|hi)|fiamm[ae]/ fullword
        $word11 = /bruciò|brucia(t[aioe]|ndo|va(no)?|(ro)?no)?|incener(ì|irono|it[aioe]|endo|iva(no)?|iscono|isce)/ fullword

        $word21 = /(((k|c|d|m|h)(-)?)?m(2|\s?²|\s?q(uadr(at)?[eoi])?))/ fullword
        $word22 = /(migli[oa]|((chilo|kilo|centi|deci|milli|etto)(-|\s)?)?(metr[oi]))(2|\s?²|\s?q(uadr(at)?[eoi])?)/ fullword 
        $word23 = /ettar[oi]|acr[oi]/ fullword 
    condition:
        (1 of ($word1*)) and (1 of ($word2*))
}


rule RoadImpact : Italian
{
meta:
    name = "road"
	description = "Rule to detect if text contains roads information"

strings:
    $word1 = /autostrad[ae]/ fullword
    $word13 = /casell[oi]/ fullword
    $word2 = /strad[ae]/ fullword
    $word3 = /statale/ fullword
    $word4 = /carreggiat[ae]/ fullword
    $word5 = /percors[oi]/ fullword
    $word6 = /tragitt[oi]/ fullword
    $word7 = /bivi[oi]/ fullword
    $word8 = /trafor[oi]/ fullword
    $word9 = /tratt[oi]/ fullword
    $word10 = /corsi[ae]/ fullword
    $word11 = /pist[ae]/ fullword
    $word12 = /vial[ie]/ fullword

condition:
	1 of them and DamageImpact
}

rule RailwayImpact : Italian
{
meta:
    name = "railway"
	description = "Rule to detect if text contains railway information"

strings:
    $word1 = /ferrovi[ae]/ fullword
    $word2 = /binari[o]?/ fullword
    $word3 = /tren[oi]/ fullword
    $word4 = /stazion[ei]/ fullword
    $word5 = /rotai[ae]/ fullword
    $word6 = /convogli[o]?/ fullword
    $word7 = /vagon[ei]/ fullword

condition:
	1 of them and DamageImpact
}

rule BridgeImpact : Italian
{
meta:
    name = "bridge"
	description = "Rule to detect if text contains bridge information"

strings:
    $word1 = /pont[ei]/ fullword
    $word2 = /viadott[oi]/ fullword
    $word3 = /cavalcavia/ fullword
    $word4 = /ponticell[oi]/ fullword

condition:
	1 of them and DamageImpact
}

rule PortImpact : Italian
{
meta:
    name = "port"
	description = "Rule to detect if text contains port information"

strings:
    $word1 = /port[oi]/ fullword
    $word2 = /scal[oi]/ fullword
    $word3 = /ancoraggi[o]?/ fullword
    $word4 = /mol[oi]/ fullword

condition:
	1 of them and DamageImpact
}

rule AirportImpact : Italian
{
meta:
    name = "airport"
	description = "Rule to detect if text contains airport information"

strings:
    $word1 = /aereoport[oi]/ fullword
    $word2 = /eliport[oi]/ fullword
    $word3 = /pist[ae] (di|d)\s+atterraggio/ fullword
    $word4 = /aerodrom[oi]/ fullword
    $word5 = /aeroportuale/ fullword
    $word6 = /camp[oi] (di|d)\saviazione/ fullword

condition:
	1 of them and DamageImpact
}

rule SchoolImpact : Italian
{
meta:
    name = "school"
	description = "Rule to detect if text contains school information"

strings:
    $word1 = /scuol[ae]/ fullword
    $word2 = /istitut[oi]/ fullword
    $word3 = /collegi[o]?/ fullword
    $word4 = /università/ fullword
    $word5 = /lice[oi]/ fullword
    $word6 = /accademi[ea]/ fullword

condition:
	1 of them and DamageImpact
}

rule HospitalImpact : Italian
{
meta:
    name = "hospital"
	description = "Rule to detect if text contains hospital information"

strings:
    $word1 = /ospedal[ei]/ fullword
    $word2 = /policlinico/ fullword
    $word3 = /clinic(a|he)/ fullword

condition:
	1 of them and DamageImpact
}

rule ResidentialImpact : Italian
{
meta:
    name = "residential"
	description = "Rule to detect if text contains residential buildings information"

strings:
    $word1 = /cas[ae]/ fullword
    $word2 = /edifici[o]?/ fullword
    $word3 = /stabil[ei]/ fullword
    $word4 = /abitazion[ei]/ fullword
    $word5 = /alloggi[o]?/ fullword
    $word6 = /appartament[oi]/ fullword
    $word7 = /(palazz[oi]|palazzin[ae])/ fullword
    $word8 = /vill([ae]|in([ae]))/ fullword
    $word9 = /reggi[ae]/ fullword
    $word10 = /casal[ei]/ fullword
    $word11 = /cottage/ fullword
    $word12 = /bait[ae]/ fullword
    $word13 = /dimor[ae]/ fullword
    $word14 = /camp[oi]/ fullword
    $word15 = /villaggi[o]?/ fullword
    $word16 = /grattaciel[io]?/ fullword

condition:
	1 of them and DamageImpact
}

rule FacilityImpact : Italian
{
meta:
    name = "facility"
	description = "Rule to detect if text contains facility information"

strings:
    $word1 = /servizi[o]?/ fullword
    $word2 = /struttur[ae] commercial[ei]/ fullword
    $word3 = /aziend[ae]/ fullword
    $word4 = /ent[ei]/ fullword
    $word5 = /uffici[oi]/ fullword
    $word6 = /società/ fullword
    $word7 = /stabiliment[oi] (balnear[ei])?/ fullword
    $word8 = /lid[oi]/ fullword
    $word9 = /ristorant[ei]/ fullword
    $word10 = /capannon[ei]/ fullword

condition:
	1 of them and DamageImpact
}

rule PowerImpact : Italian
{
meta:
    name = "power_network"
	description = "Rule to detect if text contains power buildings information"

strings:
    $word10 = /ret[ei] elettric(a|he)/ fullword
    $word20 = /(senza|priv[aieo] di) (energia elettrica|elettricità|corrente)/ fullword


condition:
	(1 of ($word1*) and DamageImpact) or (1 of ($word2*))
}

rule WaterImpact : Italian
{
meta:
    name = "water_network"
	description = "Rule to detect if text contains water buildings information"

strings:
    $word10 = /ret[ei] idric(a|he)/ fullword
    $word11 = /acquedott[oi]/ fullword
    $word12 = /approvvigionamento idrico/ fullword
    $word20 = /(senza|priv[aieo] di) acqua/ fullword

condition:
	(1 of ($word1*) and DamageImpact) or (1 of ($word2*))
}

rule CulturalHeritageImpact : Italian
{
meta:
    name = "cultural_heritage"
	description = "Rule to detect if text contains Cultural Heritage information"

strings:
    $word1 = /statu[ae]/ fullword
    $word2 = /monument[oi]/ fullword
    $word3 = /piazz[ae]/ fullword
    $word4 = /temp(io|li)/ fullword
    $word5 = /(antic(a|he) )?colonn[ae]( (grec(a|he)|roman[ae]))?/ fullword
    $word6 = /(anfi)?teatr[oi]/ fullword
    $word7 = /(dipint[io]|affresc(o|hi)|ritratt[oi]|quadr[oi])/ fullword
    $word8 = /chies[ae]/ fullword
    $word9 = /scultur[ae]/ fullword
    $word10 = /duomo/ fullword
    $word11 = /cattedral[ei]/ fullword
    $word12 = /centro storico/ fullword
    $word13 = /muse[oi]/ fullword
    $word14 = /basilic(a|he)/ fullword
    $word15 = /(scav|sit)[oi] archeologic[oi]/ fullword
    $word16 = /castell[oi]/ fullword
    $word17 = /oper[ae] d arte/ fullword

condition:
	1 of them and DamageImpact
}