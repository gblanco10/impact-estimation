rule DeadImpact : Dead
{
meta:
    name = "dead"
	description = "Italian rule to detect if text is related to some dead people"

strings:
    $word1 = /mort[aeoi]/ fullword
    $word2 = /moriv(o|i|a|amo|ate|ano)/ fullword
    $word3 = /mor(ì|irono)/ fullword
    $word4 = /muore/ fullword
    $word5 = /muoiono/ fullword
    $word6 = /(uccis(ero|[aeio])|uccision[ei])/ fullword
    $word7 = /uccid(e|ono|eva|evano|endo)/ fullword
    $word8 = /dece(ss[oi]|dut[aeoi])/ fullword
    $word9= /deced(e|ono)/ fullword
    $word10 = /decedev(o|a|amo|ano)/ fullword
    $word11 = /assassinat[aeio]/ fullword
    $word12 = /assassin(a|ano|ava|avano|ò|arono|ando)/ fullword
    $word13 = /per(de(re)?|dono|deva(no)?|se(ro)?|dendo|so)\s(la|le)(sua|loro)?(vit[ae])/ fullword
    $word14 = /(senza|privo di) vita/ fullword

condition:
	1 of them
}

rule InjuredImpact : Injured
{
meta:
    name = "injured"
	description = "Rule to detect if text is related to some injured people"

strings:
    $word1 = /ferit[aeoi]/ fullword
    $word2 = /fer(isce|iscono|iva|ivano|ì|irono|endo)/ fullword
    $word3 = /colpit[aeoi]/ fullword
    $word4 = /colp(isce|iva|iscono|ivano|ì|irono|endo)/ fullword
    $word5 = /percoss[aeoi]/ fullword
    $word6 = /accoltellat[aeoi]/ fullword
    $word7 = /accoltell(a|ano|ava|avano|ò|arono|ando)/ fullword
    $word8 = /les[aeoi]/ fullword
    $word9 = /squarciat[aeoi]/ fullword
    $word10 = /ustionat[aeoi]/ fullword

condition:
	1 of them
}

rule MissingImpact : Missing
{
meta:
    name = "missing"
	description = "Rule to detect if text is related to some missing people"

strings:
    $word1 = /scompa(re|iono|riva|rivano|rve|rì|rirono|rvero|rsero)/ fullword
    $word2 = /scompars[aeoi]/ fullword
    $word3 = /dispers[aeoi]/ fullword
    $word4 = /disper(de|dono|deva|devano|sero)/ fullword
    $word5 = /sparit[aeoi]/ fullword
    $word6 = /spar(isce|iscono|iva|ivano|ì|irono)/ fullword
    $word7 = /svanit[aeoi]/ fullword
    $word8 = /svan(isce|iscono|iva|ivano|ì|irono)/ fullword

condition:
	1 of them
}

rule EvacuatedImpact : Evacuated
{
meta:
    name = "evacuated"
	description = "Rule to detect if text is related to some evacuated people"

strings:
    $word1 = /evacua((zion[ei])|(t[aeoi])|(no|va|vano|rono))/ fullword
    $word2 = /evacu(a|ò)/ fullword
    $word3 = /sfollat[aeoi]/ fullword
    $word4 = /sfoll((ament[oi])|(att[aeoi]))/ fullword
    $word5 = /evacua((ment[oi])|(t[aeoi]))/ fullword

condition:
	1 of them
}

rule RescuedImpact : Rescued
{
meta:
    name = "rescued"
	description = "Rule to detect if text is related to some rescued people"

strings:
    $word1 = /salva((ment[oi])|(t[aeoi])|(tagg(io|i)))/ fullword
    $word2 = /salv(a|ano|ava|avano|ò|arono)/ fullword
    $word3 = /libera((zion[ei])|(t[aeoi]))/ fullword
    $word4 = /liber(a|ano|ava|avano|ò|arono)/ fullword

condition:
	1 of them
}

rule InfectedImpact : Infected
{
meta:
    name = "infected"
	description = "Rule to detect if text is related to some infected people"

strings:
    $word1 = /infe((zion[ei])|(ttat[aeoi])|tt[aeio])/ fullword
    $word2 = /(contagi[o]?|contagios[aeoi])/ fullword
    $word3 = /contamina((zion[ei])|(t[aeoi]))/ fullword

condition:
	1 of them
}

rule HospitalizedImpact : Hospitalized
{
meta:
    name = "hospitalized"
	description = "Rule to detect if text is related to some hospitalized people"

strings:
    $word1 = /malat((ti[ae])|([aeoi]))/ fullword
    $word2 = /ospedalizzat[aeoi]/ fullword
    $word3 = /ricoverat[aeoi]/ fullword
    $word4 = /ricover(ano|a|ava|avano|ò|arono)/ fullword

condition:
	1 of them
}

rule RecoveredImpact : Recovered
{
meta:
    name = "recovered"
	description = "Rule to detect if text is related to some recovered people"

strings:
    $word1 = /recuperat[aeoi]/ fullword
    $word2 = /recuper(a|ano|ava|avano|ò|arono)/ fullword
    $word3 = /soccors[aeoi]/ fullword
    $word4 = /soccor(re|rono|reva|revano|se|sero)/ fullword

condition:
	1 of them
}

rule PopulationImpact : Population
{
    meta:
        name = "population"
        description = "Rule to detect if impact mentioned in text is related to people"

    strings:
        $word1 = /person[ae]|cittadin[aeio]|popolazion[ei]|donn[ae]|uomo|uomini|tutti|chiunque|qualcun[oa]/ fullword
        $word2 = /abitant[ei]|resident[ei]|famigli[ae]/ fullword
        $word3 = /madr[ei]|mamm[ae]|padr[ei]|pap[a]|zi[oai]|parent[ei]|nipot[ei]|cugin[aioe]/ fullword
    condition:
        1 of them
}

rule OtherImpact : Other
{
    meta:
        name = "other"
        description = "Rule to detect if text is related to some other type of impact affecting people"

    strings:
        $word11 = /(senza|priv[aieo] di) (energia elettrica|elettricità|corrente)/ fullword
        $word12 = /(senza|priv[aieo] di) acqua/ fullword
        $word20 = /bloccat[aioe]|intrappolat[aeio]/
        $word21 = /(senza|priv[aieo] di) (cibo|provviste)/ fullword
    condition:
        (1 of ($word1*) and PopulationImpact) or (1 of ($word2*))
}