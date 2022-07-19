import json 
import argparse
from itertools import groupby
from collections import defaultdict

from impact_estimation.constants import infrastructure_category,population_category
from impact_estimation.utils import get_most_frequent


def get_default_result():
    result = defaultdict(dict)
    result['population'] = {c: dict() for c in population_category}
    result['infrastructures'] = {c: dict() for c in infrastructure_category}
    return result


parser = argparse.ArgumentParser()

parser.add_argument('--in',type=str,help='Path of predicted tweets',dest='IN')
parser.add_argument('--out',type=str,help='Path of output file',dest='OUT')
parser.add_argument('--filter','-f',help='If specified reports impacted categories only',action='store_true',dest='FILTER')

args = parser.parse_args()

with open(args.IN,encoding='utf-8') as f:
    data = json.load(f)

out = []

grouped_tweets = groupby(data,lambda x: x['event_id'])
for event_id, event_tweets in grouped_tweets:
    event_result = get_default_result()
    tweet_count = 0
    for tweet in event_tweets:
        tweet_count+= 1
        date = tweet['created_at']
        for rule_name in tweet['impact'].keys():
            for rule,estimate in tweet['impact'][rule_name].items():
                if date in event_result[rule_name][rule]:
                    event_result[rule_name][rule][date] = max(
                        estimate, event_result[rule_name][rule][date])
                else:
                    event_result[rule_name][rule][date] = estimate
    # Group together the results for the same event
    for type in event_result.keys():
        for k, v in event_result[type].items():
            if len(v) == 0:
                event_result[type][k] = {'impacted': False, 'count': 0}
            else:
                # check the maximum of 10 more recent tweets
                n = 100
                if len(v) <= n:
                    event_result[type][k] = {
                        'impacted': True,
                        'count': get_most_frequent(list(v.values()))
                    }
                else:
                    # convert string to date
                    dates = [d for d in v.keys()]
                    dates.sort(reverse=True)
                    event_result[type][k] = {
                        'impacted': True,
                        'count': get_most_frequent([v[dates[i]] for i in range(0, n)])
                    }
    if args.FILTER:
        event_result = {type: {k: v for k, v in event_result[type].items() if v['impacted']} for type in event_result.keys()}
    
    out.append({'event_id': event_id, 'impact': event_result,'tweets':tweet_count})

with open(args.OUT, 'w',encoding='utf-8') as f:
    json.dump(out, f, indent=4)
print("Done")