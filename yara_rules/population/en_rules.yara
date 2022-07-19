rule DeadImpact : Dead
{
meta:
    name = "dead"
	description = "English rule to detect if text is related to some dead people"

strings:
    $word1 = /(dead[s]?|death[s]?)/ fullword
    $word2 = /(die|died|dying)/ fullword
    $word3 = /deceas(e|es|ing|ed)/ fullword
    $word4 = /pass(ing|ed|es)? away/ fullword
    $word5 = /kill(s|ed|ing)?|executed/ fullword
    $word6 = /murder(s|ed|ing)?/ fullword
    $word7 = /assassinate(s)?/ fullword
    $word8 = /assassinat(ed|ing)/ fullword
    $word9 = /(lose(s)|lost|losing)\s((his|her|its|their)\s)?(life|lives)/ fullword
    $word10 = /fatalit(y|ies)/ fullword
    $word11 = /casualt(y|ies)/ fullword

condition:
	1 of them
}

rule InjuredImpact : Injured
{
meta:
    name = "injured"
	description = "Rule to detect if text is related to some injured people"

strings:
    $word1 = /injure(d|s)?/ fullword
    $word2 = /wound(s|ed|ing)/ fullword
    $word3 = /hurt(ed|s|ing)?/ fullword
    $word4 = /harm(ed|s|ing)?/ fullword
    $word5 = /offend(ed|s|ing)?/ fullword
    $word6 = /abus(ed|es|ing)?/ fullword
    $word7 = /maltreat(ed|s|ing)?/ fullword
    $word8 = /injur(y|ies|ing)?/ fullword

condition:
	1 of them
}

rule MissingImpact : Missing
{
meta:
    name = "missing"
	description = "Rule to detect if text is related to some missing people"

strings:
    $word1 = /missing/ fullword
    $word2 = /lost/ fullword
    $word3 = /disappear(s|ing|ed)?/ fullword
    $word4 = /lack(s|ed|ing)/ fullword
    $word5 = /unaccounted/ fullword
    $word6 = /(look(s|ing)?|search(ing|es)?) for/ fullword

condition:
	1 of them
}

rule EvacuatedImpact : Evacuated
{
meta:
    name = "evacuated"
	description = "Rule to detect if text is related to some evacuated people"

strings:
    $word1 = /evacuat(ed|ing)|evacuation(s)?/ fullword
    $word2 = /abandon(ing|ed)?/ fullword
    $word3 = /departed/ fullword
    $word4 = /displac(ing|ed)/ fullword

condition:
	1 of them
}

rule RescuedImpact : Rescued
{
meta:
    name = "rescued"
	description = "Rule to detect if text is related to some rescued people"

strings:
    $word1 = /rescu(ed|es|ing)/ fullword
    $word2 = /extricate(d|s)?/ fullword
    $word3 = /liberate(d|s)?/ fullword

condition:
	1 of them
}

rule InfectedImpact : Infected
{
meta:
    name = "infected"
	description = "Rule to detect if text is related to some infected people"

strings:
    $word1 = /infect(ed|s|ing)?/ fullword
    $word2 = /poison(ed|s|ing)?/ fullword
    $word3 = /contaminate(d|s)?/ fullword
    $word4 = /contaminating/ fullword

condition:
	1 of them
}

rule HospitalizedImpact : Hospitalized
{
meta:
    name = "hospitalized"
	description = "Rule to detect if text is related to some hospitalized people"

strings:
    $word1 = /hospitalized/ fullword
    $word2 = /ill/ fullword
    $word3 = /sick(ed)?/ fullword
    $word4 = /bedded/ fullword

condition:
	1 of them
}

rule RecoveredImpact : Recovered
{
meta:
    name = "recovered"
	description = "Rule to detect if text is related to some recovered people"

strings:
    $word1 = /recovered/ fullword
    $word2 = /saved/ fullword
    $word3 = /helped/ fullword

condition:
	1 of them
}

rule PopulationImpact : Population
{
    meta:
        name = "population"
        description = "Rule to detect if impact mentioned in text is related to people"

    strings:
        $word1 = /person(s)|citizen(s)|population(s)?|people|(wo)?man|(wo)?men|(every|some|any)(body|one)/ fullword
        $word2 = /inhabitant(s)?|resident(s)?|famil(y|ies)|household(s)?/ fullword
        $word3 = /mother(s)?|mom(s)?|father(s)?|dad(s)?|aunt(s)?|uncle(s)?|relative(s)?|nephew(s)?|cousin(s)?/ fullword
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
        
        $word22 = /\d+( (are|(were )?left|remain|still))? (without|with no|(has|have) no(t)?|(do not|don t|dont|does not|doesn t) have) (any )?(electric(ity?)|power)/ fullword
        $word23 = /\d+( (are|(were )?left|remain|still))? (without|with no|(has|have) no(t)?|(do not|don t|dont|does not|doesn t) have) (any )?(water)/ fullword


    condition:
        (1 of ($word1*) and PopulationImpact) or (1 of ($word2*))
}