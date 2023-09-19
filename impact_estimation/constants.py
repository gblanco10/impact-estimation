# definition of rule names to match for each category
infrastructure_category = ["road", "railway", "bridge", "port", "airport", "school", "hospital", "residential",
                           "facility", "power_network", "water_network", "cultural_heritage","area","emission"]
population_category = ["dead", "injured", "missing", "evacuated", "rescued", "infected", "hospitalized", "recovered","other"]
impact_category = ['NotDigitKeywords','SignKeywords']
max_num_infrastructures = 1000000
max_num_population = 1000000
spacy_pipeline_map = {
    'en':"en_core_web_trf",
    'it':"it_core_news_lg",
    'es':"es_dep_news_trf"
}
unitary_rules = list(set(infrastructure_category) - {"residential","area","emission"})
# to detect a true number that refers to an impact, rules which name is in the list impact_category will be used