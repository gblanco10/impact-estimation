rule DamageImpact : Damage
{
meta:
    name = "damage"
	description = "Spanish rule to detect if text is related to some damage "

strings:
    $word1 = /deslizó|desliz(aron|a(n)?|aba(n)?|a(n)?d[oa]|amiento)/ fullword
    $word2 = /colapsó|colaps(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])|derrumbó|derrumb(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])|desplomó|desplom(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])/ fullword
    $word3 = /cerró|cerr(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])|bloqueó|bloque(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])|clausuró|clausur(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])/ fullword
    $word4 = /interrupción|interrupciones|interrumpió|interrump(ieron|ir|e(n)?|ía(n)?|iendo|id[oe])|suspensión|suspendió|suspen(dieron|de(r|n)?|día(n)?|diendo|did[oe]|s[oe])/ fullword
    $word5 = /(daños|dañó|daña(ron|r|n)?|daña(n)?d[ae]|dañaba(n)?)/ fullword
    $word6 = /destrucción|destrucciones|destruyó|destru(yeron|ir|e(n)?|ía(n)?|yendo|id[oe])/ fullword
    $word7 = /demolición|demoliciones|demolió|dem(olieron|uele(r|n)?|olía(n)?|oliendo|olid[oe])/ fullword
    $word8 = /devastación|devastaciones|devast(aron|ó|o|a(r|n)?|aba(n)?|ando|ad[oe])/ fullword
    $word9 = /(ruin[ae]|restos|arruinó|arruinaron|arruina(n)?d[ao]|arruina(ba)?(n)?)/ fullword
    $word10 = /(choque(s)?|estrelló|estrellaron|estrellad[ao]|estrellándose|estrellaba(n)?)/ fullword
    $word11 = /cae(r|n)?|cayó|cayeron|caíd[ao]|caía(n)?|cayendo/ fullword
    $word12 = /desprendió|desprend(ieron|e(n)?|ía(n)?|ido|imiento(s)?)/ fullword
    $word13 = /devastó|devasta(ron|r|n|ba|ban|ndo|d[oa])/ fullword
    $word14 = /quemó|quema(ron|r|n|ba|ban|ndo|d[oa])?|incendi(aron|ó|o|ado)|incendi(o|a(r|n)?|aba(n)?|ando|ad[oe])|hoguer[ao]/ fullword
    $word15 = /golpeó|golpea(ron|r|n|ba|ban|ndo|d[oa])/ fullword
    $word16 = /inundó|inunda(ron|r|n|ba|ban|ndo|d[oa])|desbordó|desbord(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])|sumergió|sumerg(ieron|ir|e(n)?|ía(n)?|iendo|id[oe])|inundación(es)?|aluvión(es)?/ fullword
    $word17 = /explotad[oaie]|estallad[oaie]|explosión|explotó|explot(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])|estalló|estall(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])/ fullword
    $word18 = /tomrmenta(s)|tempestad|hurac(án|anes)|borrasca|temporal|lluvia|tornado(s)?|precipitaci(ón|ones)/ fullword
    $word19 = /terremoto(s)?|sismo(s)?|seísmo(s)?|temblor(es)?|movimiento sísmico|avalancha|alud/ fullword
    $word20 = /desintegración|desintegraciones|desintegró|desintegr(aron|o|a(r|n)?|aba(n)?|ando|ad[oe])|ruptura|rompió|romp(ieron|e(r|n)?|ía(n)?|iendo|id[oe])|rot[aoe]/ fullword
    
    $word30 = /sin (electricidad|energía eléctrica)/ fullword
    $word31 = /sin( el)? agua/ fullword
condition:
	1 of them
}

rule Co2EmissionImpact: Max
{
    meta:
        name = "emission"
        decription = "Rule to detect if text is related to co2 emission"
    strings:
        $word10 = /dióxido de carbono|co2|co²|dióxido de carbón|anhídrido carbónico|gas carbónico|ácido carbónico/ fullword
        
        $word20 = /emisiones|emit(e(n)?|ía(n)?|ido|iendo)/ fullword

        $word30 = /tonelada(s)?|quintal(es)?|(chilo|kilo|k(iló)?)\s?g(ramo(s)?)?/ fullword
    condition:
        (1 of ($word1*)) and (1 of ($word2*)) and (1 of ($word3*)) 

}

rule BurnedAreaImpact: Max
{
    meta:
        name = "area"
	    description = "Rule to detect if text is related to some burned area "
    strings:
        $word10 = /quemó|quema(ron|r|n|ba|ban|ndo|d[oa])?|incendi(o|ado)|incendi(o|a(r|n)?|aba(n)?|ando|ad[oe])|hoguer[ao]/ fullword
        
        $word21 = /(((k|c|d|m|h)(-)?)?m(2|\s?²|\s?c(uadr(ad)?[eoi](s)?)?))/ fullword
        $word22 = /(milla(s)?|pies|((chilo|kilo|kiló|centí|centi|mili|deci|decí|milí|hectó)(-|\s)?)?(metro(s)?(2|\s?²|\s?c(uadr(ad)?[aeoi](s)?)?)))/ fullword 
        $word23 = /hectárea(s)?|acre(s)?/
    condition:
        (1 of ($word1*)) and (1 of ($word2*))
}


rule RoadImpact : Road
{
meta:
    name = "road"
	description = "Rule to detect if text contains roads information"

strings:
    $word1 = /carretera[s]?/ fullword
    $word2 = /artería[s]?/ fullword
    $word3 = /ruta[s]?/ fullword
    $word4 = /autopista/ fullword
    $word5 = /calzada[s]?/ fullword
    $word6 = /itinerari(os|a|o)/ fullword
    $word7 = /calle(s)?/ fullword
    $word8 = /vial(os)?/ fullword
    $word9 = /trayecto(s)?/ fullword
    $word10 = /peaje(s)?/ fullword

condition:
	1 of them and DamageImpact
}

rule RailwayImpact : Railway
{
meta:
    name = "railway"
	description = "Rule to detect if text contains railway information"

strings:
    $word1 = /(ferrocarril|vía(s)? férrea(s)?)/ fullword
    $word2 = /tren[es]?/ fullword
    $word3 = /(binario|pistas)/ fullword
    $word4 = /vagón(es)?/ fullword
    $word5 = /metro/ fullword
    $word6 = /convoy/ fullword
    $word7 = /ferroviario/ fullword
    $word8 = /carro/ fullword

condition:
	1 of them and DamageImpact
}

rule BridgeImpact : Bridge
{
meta:
    name = "bridge"
	description = "Rule to detect if text contains bridge information"

strings:
    $word1 = /puente[s]?/ fullword
    $word2 = /viaducto[s]?/ fullword
    $word3 = /paso elevado/ fullword

condition:
	1 of them and DamageImpact
}

rule PortImpact : Port
{
meta:
    name = "port"
	description = "Rule to detect if text contains port information"

strings:
    $word1 = /puerto[s]?/ fullword
    $word2 = /ancla[s]?/ fullword
    $word3 = /embarcadero[s]?/ fullword
    $word4 = /muelle[s]?/ fullword

condition:
	1 of them and DamageImpact
}

rule AirportImpact : Airport
{
meta:
    name = "airport"
	description = "Rule to detect if text contains airport information"

strings:
    $word1 = /aeropuerto[s]?/ fullword
    $word2 = /helipuerto[s]?/ fullword
    $word3 = /avión[es]?/ fullword
    $word4 = /aeródromo[s]?/ fullword
    $word5 = /pista de aterrizaje/ fullword
    $word6 = /campo de aviación/ fullword
    $word7 = /campo aéreo/ fullword

condition:
	1 of them and DamageImpact
}

rule SchoolImpact : School
{
meta:
    name = "school"
	description = "Rule to detect if text contains school information"

strings:
    $word1 = /(colegio|escuela[s]?)/ fullword
    $word2 = /academia[s]?/ fullword
    $word3 = /universidad[es]?/ fullword
    $word4 = /facultad[es]?/ fullword

condition:
	1 of them and DamageImpact
}

rule HospitalImpact : Hospital
{
meta:
    name = "hospital"
	description = "Rule to detect if text contains hospital information"

strings:
    $word1 = /hospital[es]?/ fullword
    $word2 = /clínica[s]?/ fullword
    $word3 = /cirugía[s]?/ fullword

condition:
	1 of them and DamageImpact
}

rule ResidentialImpact : Residential
{
meta:
    name = "residential"
	description = "Rule to detect if text contains residential buildings information"

strings:
    $word1 = /(casa[s]?|hogares)/ fullword
    $word2 = /(plano[s]?|apartamento[s]?)/ fullword
    $word3 = /palacio[s]?/ fullword
    $word4 = /condominio[s]?/ fullword
    $word5 = /bungalow[s]?/ fullword
    $word6 = /domicilio[s]?/ fullword
    $word7 = /resort[s]?/ fullword
    $word8 = /cabaña[s]?/ fullword
    $word9 = /vivienda[s]?/ fullword
    $word10 = /(tienda[s]?|carpas)/ fullword
    $word12 = /pueblo[s]?/ fullword
    $word13 = /(acampar|campamento[s]?)/ fullword
    $word14 = /(zona[s]?)/ fullword

condition:
	1 of them and DamageImpact
}

rule FacilityImpact : Facility
{
meta:
    name = "facility"
	description = "Rule to detect if text contains facility information"

strings:
    $word1 = /instalacion(es)?/ fullword
    $word2 = /(organización|organizaciones)/ fullword
    $word3 = /empresa(s)?/ fullword
    $word4 = /oficina[s]?/ fullword

condition:
	1 of them and DamageImpact
}

rule PowerImpact : Power
{
meta:
    name = "power_network"
	description = "Rule to detect if text contains power buildings information"

strings:
    $word10 = /red[es]? eléctrica[s]?/ fullword
    $word11 = /red[es]? de energía[s]?/ fullword
    $word12 = /(alimentación|suministro) de energía/ fullword
    $word20 = /sin (electricidad|energía eléctrica)/ fullword

condition:
	(1 of ($word1*) and DamageImpact) or (1 of ($word2*))
}

rule WaterImpact : Water
{
meta:
    name = "water_network"
	description = "Rule to detect if text contains water buildings information"

strings:
    $word10 = /red[es]? de agua[s]?/ fullword
    $word11 = /acueducto/ fullword
    $word12 = /(tubería|cañería) de agua[s]?/ fullword
    $word20 = /sin( el)? agua/ fullword

condition:
	(1 of ($word1*) and DamageImpact) or (1 of ($word2*))
}

rule CulturalHeritageImpact : CulturalHeritage
{
meta:
    name = "cultural_heritage"
	description = "Rule to detect if text contains Cultural Heritage buildings information"

strings:
    $word1 = /estatua[s]?/ fullword
    $word2 = /monument(o|i|um)/ fullword
    $word3 = /plaza[s]/ fullword
    $word4 = /templo[s]?/ fullword
    $word5 = /(anfi)?teatro[s]?/ fullword
    $word6 = /etapa[s]?/ fullword
    $word7 = /museo[s]?/ fullword
    $word8 = /(pintura|retrato|cuadro|ilustracione)[s]?/ fullword
    $word9 = /centro histórico/ fullword
    $word10 = /(yacimiento|sitio|excavación) arqueológica/ fullword
    $word11 = /(iglesia|catedral|basílica)(es|s)?/ fullword
    $word12 = /castillo(s)?/ fullword
    $word13 = /(pieza|obra(s)?) (maestra|de arte)/ fullword

condition:
	1 of them and DamageImpact
}