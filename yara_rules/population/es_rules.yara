rule DeadImpact : Dead
{
meta:
    name = "dead"
	description = "Spanish rule to detect if text is related to some dead people"

strings:
    $word1 = /muert[aoe][s]?/ fullword
    $word2 = /muer(e|en)/ fullword
    $word3 = /moría(n)?/ fullword
    $word4 = /muri(ó|eron)/ fullword
    $word5 = /fallecid[ao][s]?/ fullword
    $word6 = /fallec(er|iendo)/ fullword
    $word7 = /mat(an|ado|aba|aban|aron|ó|ando)/ fullword
    $word8 = /asesin(an|ado|aba|aban|ada|adas|ados|aron|ó|ando)?/ fullword
    $word9 = /(pierde(n)?|per(der|día(n)?|diendo))\s(su(s)?|suy[ao](s)?)?(vida)/ fullword
    $word10 = /sin vida/ fullword


condition:
	1 of them
}

rule InjuredImpact : Injured
{
meta:
    name = "injured"
	description = "Rule to detect if text is related to some injured people"

strings:
    $word1 = /lesionad[ao][s]?/ fullword
    $word2 = /lesion(a|an|aba|aban|ó|aron|ando)/ fullword
    $word3 = /herid[ao][s]?/ fullword
    $word4 = /(hiere|hería)(n)?/ fullword
    $word5 = /hirió|hirieron/ fullword

condition:
	1 of them
}

rule MissingImpact : Missing
{
meta:
    name = "missing"
	description = "Rule to detect if text is related to some missing people"

strings:
    $word1 = /desaparecid[ao][s]?/ fullword
    $word2 = /desaparec(e|en|ía|ían|ió|ieron)/ fullword
    $word3 = /perdid[ao][s]?/ fullword
    $word5 = /perd(ía|ían|ió|ieron)/ fullword

condition:
	1 of them
}

rule EvacuatedImpact : Evacuated
{
meta:
    name = "evacuated"
	description = "Rule to detect if text is related to some evacuated people"

strings:
    $word1 = /evacuad[ao][s]?/ fullword
    $word2 = /evacu(a|an|aba|aban|ó|aron)/ fullword
    $word3 = /abandonad[ao][s]?/ fullword
    $word4 = /salid[ao][s]?/ fullword
    $word5 = /desplazad[ao][s]?/ fullword
    $word6 = /desplaz(a|an|aba|aban|ó|aron)/ fullword

condition:
	1 of them
}

rule RescuedImpact : Rescued
{
meta:
    name = "rescued"
	description = "Rule to detect if text is related to some rescued people"

strings:
    $word1 = /rescatad[ao][s]?/ fullword
    $word2 = /rescat(a|an|aba|aban|ó|aron)/ fullword
    $word3 = /liberad[ao][s]?/ fullword
    $word4 = /liber(a|an|aba|aban|ó|aron)/ fullword

condition:
	1 of them
}

rule InfectedImpact : Infected
{
meta:
    name = "infected"
	description = "Rule to detect if text is related to some infected people"

strings:
    $word1 = /infectad[ao][s]?/ fullword
    $word2 = /infect(a|an|aba|aban|ó|aron)/ fullword
    $word4 = /envenenad[ao][s]?/ fullword
    $word5 = /envenen(a|an|aba|aban|ó|aron)/ fullword

condition:
	1 of them
}

rule HospitalizedImpact : Hospitalized
{
meta:
    name = "hospitalized"
	description = "Rule to detect if text is related to some hospitalized people"

strings:
    $word1 = /hospitalizad[ao][s]?/ fullword
    $word2 = /enferm[ao][s]?/ fullword
    $word3 = /enfermad[ao][s]?/ fullword
    $word4 = /enferm(a|an|aba|aban|ó|aron)/ fullword


condition:
	1 of them
}

rule RecoveredImpact : Recovered
{
meta:
    name = "recovered"
	description = "Rule to detect if text is related to some recovered people"

strings:
    $word1 = /recuperad[ao][s]?/ fullword
    $word2 = /recuper(a|an|aba|aban|ó|aron)/ fullword
    $word3 = /salvad[ao][s]?/ fullword
    $word4 = /salv(a|an|aba|aban|ó|aron)/ fullword
    $word5 = /recobrad[ao][s]?/ fullword


condition:
	1 of them
}

rule PopulationImpact : Population
{
    meta:
        name = "population"
        description = "Rule to detect if impact mentioned in text is related to people"

    strings:
        $word1 = /persona(s)?|alguien|ciudadan[oa](s)?|población(s)?|poblaciones|hombre(s)?|mujer(es)?|todo(s)?|cualquiera/ fullword
        $word2 = /habitante(s)?|residente(s)?|familia(s)?/ fullword
        $word3 = /mamá(s)?|madre(s)?|padre(s)?|papá|tí[oa](s)?|relativ[oa](s)?|niet[oa](s)?|prim[oa](s)?/ fullword
    condition:
        1 of them
}

rule OtherImpact : Other
{
    meta:
        name = "other"
        description = "Rule to detect if text is related to some other type of impact affecting people"

    strings:
        $word11 = /(without|with no|(has|have) no(t)?|(do not|don t|dont|does not|doesn t) have) (any )?(electric(ity?)|power)/ fullword
        $word12 = /(without|with no|(has|have) no(t)?|(do not|don t|dont|does not|doesn t) have) (any )?(water)/ fullword
        $word20 = /blocked|trapped/
        $word21 = /(without|with no|(has|have) no(t)?|(do not|don t|dont|does not|doesn t) have) (any )?(food|supplies)/ fullword
    condition:
        (1 of ($word1*) and PopulationImpact) or (1 of ($word2*))
}