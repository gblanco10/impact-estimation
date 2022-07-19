import json 
import argparse

import argparse

import json
import os

from impact_estimation.RuleYara import RuleYara
from impact_estimation.constants import *
from impact_estimation.utils import combine_matches, clean_text, calculate_impact

from tqdm import tqdm

# spacy pipeline
import spacy

from time import time
# Read parameters
parser = argparse.ArgumentParser()
parser.add_argument('--in','-o',help='Events Tweets input file',dest='INPUT')
parser.add_argument('--out','-i',help='Events Tweets output file',dest='OUTPUT')

args = parser.parse_args()

supported_lans = "en,es,it"
rule_path = "yara_rules"

# compile yara rules
infrastructure_rules = RuleYara(name="infrastructures", rule_names=infrastructure_category)
population_rules = RuleYara(name="population", rule_names=population_category)
impact_rules = RuleYara(name="impact", rule_names=impact_category)

for lan in supported_lans.split(","):
    infrastructure_rules.add_rule(
        rule_filepath=os.path.join(os.path.join(rule_path, 'infrastructure'), f"{lan}_rules.yara"), lan=lan)
    population_rules.add_rule(
        rule_filepath=os.path.join(os.path.join(rule_path, 'population'), f"{lan}_rules.yara"), lan=lan)
    impact_rules.add_rule(rule_filepath=os.path.join(os.path.join(rule_path, 'impact'), f"{lan}_rules.yara"),
                          lan=lan)
impact_rules.add_rule(rule_filepath=os.path.join(os.path.join(rule_path, 'impact'), f"generic_rules.yara"),
                      lan='all')

# Load spacy pipelines
start=time()
spacy_pipelines = {k:spacy.load(v) for k,v in spacy_pipeline_map.items()}
elapsed = time()-start
print(f"Spacy pipelines for supported languages loaded in {elapsed} seconds")


with open(args.INPUT,encoding='utf-8') as f:
    tweets_data = json.load(f)

for tweet in tqdm(tweets_data):
    tweet_lang = tweet['lang']
    tweet_text, tweet_graph, tweet_sentences = clean_text(
        tweet['text'], spacy_pipelines[tweet_lang], tweet_lang)
    tweet_matches = []
    for sentence in tweet_sentences:
        for rule in (population_rules, infrastructure_rules):
            # apply keywords rules
            matches = rule.apply_yara_rule(text=sentence['text'],
                                            lan=tweet_lang,
                                            apply_lower=True)
            # matches is a list of {'word': , 'rule': }
            for m in matches:
                # estimate impact looking at numbers in text
                for word, pos in zip(m['word'], m['pos']):
                    nums = calculate_impact(sentence=sentence['text'],
                                            pos_word=pos+sentence['start'],
                                            matching_word=word,
                                            sentence_start=sentence['start'],
                                            impact_rule=impact_rules,
                                            lan=tweet_lang,
                                            text=tweet_text)
                    tweet_matches.append({
                        'rule': m['rule'],
                        'word': word,
                        'nums': nums,
                        'pos': pos+sentence['start']
                    })

    tweet_result = combine_matches(tweet_lang, tweet_matches, tweet_graph)
    est_result = {}
    for rule, content in tweet_result.items():
        estimate = content['value']
        word = content['word']
        if rule in infrastructure_category:
            rule_name = 'infrastructures'
            if estimate >= max_num_infrastructures:
                continue
        if rule in population_category:
            rule_name = 'population'
            if estimate >= max_num_population:
                continue
        if rule_name not in est_result:
            est_result[rule_name] = {}
        est_result[rule_name][rule] = estimate
    tweet['impact'] = est_result

with open(args.OUTPUT,'w',encoding='utf-8') as f:
    json.dump(tweets_data,f,indent=3)

print("DONE")