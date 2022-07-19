rule DamageImpact : Damage
{
meta:
    name = "damage"
	description = "English rule to detect if text is related to some damage "

strings:
    $word1 = /land(slide[s]?|slip[s]?)|avalanche(s)?|rock\s?slide(s)?|mudslide(s)?|subsidence(s)?/ fullword
    $word2 = /rockfall[s]?/ fullword
    $word3 = /collapse(d|s)?|collapsing|downfall(s)?/ fullword
    $word4 = /clos(e(s)?|ed|ure|ing)/ fullword
    $word5 = /(inter|dis)rupt(s?|ed|ion[s]?|ing)|suspen(ded|d(s)?|t|ding|sion(s)?)/ fullword
    $word6 = /(damag|compromis|degrad)(e[sd]?|ing)/ fullword
    $word7 = /destruct(ion(s)?|s|ed|ing)?/ fullword
    $word8 = /demoli(tion(s)?|shed|sh(es)?)/ fullword
    $word9 = /destroy(ed|ing|s)?/ fullword
    $word10 = /ruin(s|ed|ing)?/ fullword
    $word11 = /crash(ed|ing|es)?/ fullword
    $word12 = /(fall(s|ing)?|fell|fallen) down/ fullword
    $word13 = /(wild|bush)?fire(s)?|flame(s)?|firing/ fullword
    $word14 = /(break(s|ing)?|broke|broken)\s?(down)?/ fullword
    $word15 = /fault(s|ing|ed)?/ fullword
    $word16 = /failure(d|s|ing)?|fail(s|ed|ing)?/ fullword
    $word17 = /flood(ed|s|ing)?|inundat(ion(s)?|e(s)?|ed|ing)/ fullword
    $word18 = /hit(s|ting)?/ fullword
    $word19 = /burn(ed|s|ing|t)?|torch(es|ed|ing)?/ fullword
    $word20 = /devastat(ion(s)?|e(s)?|ed|ing)|crush(es|ed|ing)?/ fullword
    $word21 = /storm(s|ed|ing)?|hurricane(s)?|tornado(s)?|rain(s|ed|ing)?|tempest(s)?|temporal(s)?|blizzard(s)?|cyclone(s)?|typhoon(s)?/ fullword
    $word22 = /spoil(t|s|ed|ing)?/ fullword
    $word23 = /deteriorat(e(s)?|d|ing)/ fullword
    $word24 = /explosion(s)|exploded|detonat(ion(s)?|e(s)?|ed|ing)/ fullword
    $word25 = /earthquake(s)?|seism(s)?|tremor(s)?|quake(s|ed|ing)?/ fullword
    $word26 = /raz(ed|es|ing|e)?/ fullword
    $word27 = /(blow(s|ing|n)?|blew|wash(es|ed|ing)?) away/ fullword
    $word28 = /(rip(s|ped|ping)?|cut(s|ting)?) off/ fullword
    $word29 = /(sweep(s|ing)?|swept|tear(s|ing)?|tore|torn) through/ fullword

    $word30 = /(without|with no|(has|have) no(t)?|(do not|don t|dont|doesnt|does not|doesn t) have) (any )?(electric(ity?)|power)/ fullword
    $word31 = /(electric(ity?)|power) (outages|shortage)/ fullword
    $word32 = /blackout(s)?/ fullword
    $word33 = /(without|with no|(has|have) no(t)?|(do not|don t|dont|doesnt|does not|doesn t) have) (any )?(water)/ fullword

condition:
	1 of them
}

rule Co2EmissionImpact: Max
{
    meta:
        name = "emission"
        decription = "Rule to detect if text is related to co2 emission"
    strings:
        $word10 = /co2|carbon(\s?dioxide)|co²/ fullword
        
        $word20 = /((foot)?print|emission(s)?|emit(s|ted|ting)?)/ fullword

        $word30 = /(mega)?ton((ne)?s)?/ fullword
    condition:
        (1 of ($word1*)) and (1 of ($word2*)) and (1 of ($word3*)) 

}


rule BurnedAreaImpact: Max
{
    meta:
        name = "area"
	    description = "Rule to detect if text is related to some burned area "
    strings:
        $word10 = /(wild|bush)?fire(s)?|flame(s)?|firing|destroy(ed|ing|s)?|scorch(ed|ing|es)?/ fullword nocase
        $word11 = /burn(ed|s|ing|t)?|torch(es|ed|ing)?|destroyed/ fullword nocase

        $word21 = /(sq(uare(d)?)?)\s?(in|ft(s)?|yd(s)?|mi|((k|c|d|m|h)(-)?)?m)/ fullword nocase
        $word22 = /(sq(uare(d)?)?)\s?(inch(es)?|feet(s)?|yard(s)?|mile(s)?|((kilo|centi|deci|milli|hecto)(-|\s)?)?((meter|metre)(s)?))/ fullword nocase

        $word23 = /(in|ft(s)?|yd(s)?|mi|((k|c|d|m|h)(-)?)?m)(2|\s?²|\s?sq(uare(d)?)?)/ fullword nocase
        $word24 = /(inch(es)?|feet(s)?|yard(s)?|mile(s)?|((kilo|centi|deci|milli|hecto)(-|\s)?)?((meter|metre)(s)?))(2|\s?²|\s?sq(uare(d)?)?)/ fullword nocase
        $word25 = /hectar(e)?(s)?|ha|acre(s)?/ fullword nocase

    condition:
        (1 of ($word1*)) and (1 of ($word2*))
}

rule RoadImpact : Road
{
meta:
    name = "road"
	description = "Rule to detect if text contains roads information"

strings:
    $word1 = /road[s]?/ fullword
    $word2 = /arter(y|ies)/ fullword
    $word3 = /pathway[s]?/ fullword
    $word4 = /highway[s]?/ fullword
    $word5 = /roadway[s]?/ fullword
    $word6 = /route[s]?/ fullword
    $word7 = /itinerar(y|ies)/ fullword
    $word8 = /lane[s]?/ fullword
    $word9 = /avenue[s]?/ fullword
    $word10 = /street[s]?/ fullword
    $word11 = /motorway(\sexit[s]?)?/ fullword

condition:
	1 of them and DamageImpact
}

rule RailwayImpact : Railway
{
meta:
    name = "railway"
	description = "Rule to detect if text contains railway information"

strings:
    $word1 = /railway[s]?/ fullword
    $word2 = /tracks/ fullword
    $word3 = /train line[s]?/ fullword
    $word4 = /platform[s]?/ fullword
    $word5 = /train[s]?/ fullword
    $word6 = /railroad[s]?/ fullword
    $word7 = /subway[s]?/ fullword
    $word8 = /wagon[s]?/ fullword
    $word9 = /rail line[s]?/ fullword

condition:
	1 of them and DamageImpact
}

rule BridgeImpact : Bridge
{
meta:
    name = "bridge"
	description = "Rule to detect if text contains bridge information"

strings:
    $word1 = /bridge[s]?/ fullword
    $word2 = /viaduct[s]?/ fullword
    $word3 = /overpass/ fullword
    $word4 = /deck/ fullword

condition:
	1 of them and DamageImpact
}

rule PortImpact : Port
{
meta:
    name = "port"
	description = "Rule to detect if text contains port information"

strings:
    $word1 = /(sea)?port[s]?/ fullword
    $word2 = /harbor[s]?/ fullword
    $word3 = /anchorage[s]?/ fullword
    $word4 = /porthole[s]?/ fullword

condition:
	1 of them and DamageImpact
}

rule AirportImpact : Airport
{
meta:
    name = "airport"
	description = "Rule to detect if text contains airport information"

strings:
    $word1 = /airport[s]?/ fullword
    $word2 = /heliport[s]?/ fullword
    $word3 = /plane[s]?/ fullword
    $word4 = /airfield[s]?/ fullword
    $word5 = /air\s?terminal[s]?/ fullword
    $word6 = /aerodrome[s]?/ fullword

condition:
	1 of them and DamageImpact
}

rule SchoolImpact : School
{
meta:
    name = "school"
	description = "Rule to detect if text contains school information"

strings:
    $word1 = /school[s]?/ fullword
    $word2 = /academ(y|ies)/ fullword
    $word3 = /universit(y|ies)/ fullword
    $word4 = /institution(s)?/ fullword
    $word5 = /college/ fullword
    $word6 = /facult(y|ies)/ fullword

condition:
	1 of them and DamageImpact
}

rule HospitalImpact : Hospital
{
meta:
    name = "hospital"
	description = "Rule to detect if text contains hospital information"

strings:
    $word1 = /hospital[s]?/ fullword
    $word2 = /clinic[s]?/ fullword
    $word3 = /emergency room[s]?/ fullword
    $word4 = /surger(y|ies)?/ fullword
    $word5 = /health service[s]?/ fullword

condition:
	1 of them and DamageImpact
}

rule ResidentialImpact : Residential
{
meta:
    name = "residential"
	description = "Rule to detect if text contains residential buildings information"

strings:
    $word1 = /home[s]?/ fullword
    $word2 = /apartment[s]?/ fullword
    $word3 = /palace[s]?/ fullword
    $word4 = /condominium[s]?/ fullword
    $word5 = /bungalow[s]?/ fullword
    $word6 = /houses[s]?/ fullword
    $word7 = /domicile[s]?/ fullword
    $word8 = /resort[s]?/ fullword
    $word9 = /cottage[s]?/ fullword
    $word10 = /dwelling[s]?/ fullword
    $word12 = /village[s]?/ fullword
    $word13 = /tent[s]?/ fullword
    $word14 = /camp[s]?/ fullword
    $word16 = /building[s]?/ fullword
    $word17 = /settlement[s]?/ fullword
    $word18 = /residence[s]?/ fullword
    $word19 = /neighbourhood[s]?/ fullword
    $word20 = /localit(ies|y)/ fullword
    $word21 = /town[s]?/ fullword
    $word22 = /cit(y|ies)?/ fullword
    $word23 = /propert(y|ies)?/ fullword

condition:
	1 of them and DamageImpact
}

rule FacilityImpact : Facility
{
meta:
    name = "facility"
	description = "Rule to detect if text contains facility information"

strings:
    $word1 = /facility(ies)?/ fullword
    $word2 = /organization[s]?/ fullword
    $word3 = /company(ies)?/ fullword
    $word4 = /institution[s]?/ fullword
    $word5 = /office[s]?/ fullword
    $word6 = /restaurant[s]?/ fullword

condition:
	1 of them and DamageImpact
}

rule PowerImpact : Power
{
meta:
    name = "power_network"
	description = "Rule to detect if text contains power buildings information"

strings:
    $word10 = /(electric(ity?)|power) (network|system|grid)[s]?/ fullword

    $word20 = /(without|with no|(has|have) no(t)?|(do not|don t|dont|doesnt|does not|doesn t) have) (any )?(electric(ity?)|power)/ fullword
    $word21 = /(electric(ity?)|power) (outages|shortage)/ fullword
    $word22 = /blackout(s)?/ fullword

condition:
	(1 of ($word1*) and DamageImpact) or (1 of ($word2*))
}

rule WaterImpact : Water
{
meta:
    name = "water_network"
	description = "Rule to detect if text contains water buildings information"

strings:
    $word10 = /water suppl(y|ies)/ fullword
    $word11 = /water\s+network[s]?/ fullword
    $word12 = /water (distribution|delivery|provision)/ fullword
    $word13 = /aqueduct/ fullword
    $word20 = /(without|with no|(has|have) no(t)?|(do not|don t|dont|doesnt|does not|doesn t) have) (any )?(water)/ fullword

condition:
	(1 of ($word1*) and DamageImpact) or (1 of ($word2*))
}

rule CulturalHeritageImpact : CulturalHeritage
{
meta:
    name = "cultural_heritage"
	description = "Rule to detect if text contains cultural_heritage buildings information"

strings:
    $word1 = /statue[s]?/ fullword
    $word2 = /monument[s]?/ fullword
    $word3 = /square[s]|plaza/ fullword
    $word4 = /temple[s]?/ fullword
    $word5 = /(amphi|anfi|anphi)?theater[s]?/ fullword
    $word6 = /stadium/ fullword
    $word7 = /museum/ fullword
    $word8 = /painting|potrait/ fullword
    $word9 = /monumentum/ fullword
    $word10 = /church(es)?/ fullword
    $word11 = /cathedral(s)?/ fullword
    $word12 = /sculpture(s)?/ fullword
    $word13 = /historic center/ fullword
    $word14 = /archaeological (site|excavation)/ fullword
    $word15 = /castle(s)?/ fullword
    $word16 = /(work(s)?|piece(s)?) of art/ fullword
    $word17 = /artwork(s)?/ fullword


condition:
	1 of them and DamageImpact
}