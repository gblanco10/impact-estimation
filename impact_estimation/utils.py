from typing import List

from impact_estimation.RuleYara import RuleYara
from impact_estimation.cardinal_words import worden2num, wordit2num, wordes2num
import re
import networkx as nx
from impact_estimation.constants import unitary_rules

HASHTAG_PATTERN = "#(?P<entity>\w+)"

LINKS_PATTERN = "https?://\S+"
RT_PATTERN = "RT @\w+:\s"
NOT_UNICODE_PATTERN = "[^\x00-\xff€£$¥]"
TAG_PATTERN = '@\S+\s'
PUNTUACTION = '[\'\(\)\[\]\+~<>\n\xa0]'

SENTENCE_PUNTUACTION = "(?P<punt>[?;!])"

RECONSTRUCT_PATTERN = "((?<=\D)\s(?P<punt>[.,:?;!]))"

NUMBERS_PUNTUACTION = "((?<!\d)(?P<punt>[.,:])(?=[\s\w]))|((?<=[\s\w])(?P<punt1>[.,:])(?!\d))"

DELETE_PATTERN = LINKS_PATTERN + '|' + RT_PATTERN + '|' + NOT_UNICODE_PATTERN + '|' + TAG_PATTERN + '|' + PUNTUACTION

AREA_UNIT_MEASURE_PATTERN = {
    'en': {
        'in(ch(es)?)?': 6.4516e-10,
        'feet|ft': 9.2903e-8,
        'yd|yard(s)?': 8.3616e-7,
        'ha|hectar(e)?': 0.01,
        'acre(s)?':0.00404,
        'mi(le(s)?)?': 2.5899,
        '(k(ilo)?)(m(eter|etre(s)?)?)': 1,
        '(h(ecto)?)(m(eter|etre(s)?)?)': 0.01,
        '(d(eci)?)(m(eter|etre(s)?)?)': 1e-8,
        '(c(enti)?)(m(eter|etre(s)?)?)': 1e-10,
        '(m(illi)?)(m(eter|etre(s)?)?)': 1e-12,
        '(m(eter|etre(s)?)?)': 1e-6,
    },
    'it': {
        'ettar[oi]': 0.01,
        'migli[oa]': 2.5899,
        'acr[oi]':0.00404,
        '((ch|k)(ilo)?)(m(etr[oi])?)': 1,
        '(etto|h)(m(etr[oi])?)': 0.01,
        '(d(eci)?)(m(etr[oi])?)': 1e-8,
        '(c(enti)?)(m(etr[oi])?)': 1e-10,
        '(m(illi)?)(m(etr[oi])?)': 1e-12,
        '(m(etr[oi])?)': 1e-6
    },
    'es': {
        'hectárea(s)?': 0.01,
        'acre(s)?':0.00404,
        'pies': 9.2903e-8,
        'milla(s)?': 2.5899,
        '(h(ectó)?)(m(etro(s)?)?)': 0.01,
        '((ch|k)(ilo|iló|)?)(m(etro(s)?)?)': 1,
        '(d(ecí|eci)?)(m(etro(s)?)?)': 1e-8,
        '(c(entí|enti)?)(m(etro(s)?)?)': 1e-10,
        '(m(ilí|ili)?)(m(etro(s)?)?)': 1e-12,
        '(m(etro(s)?)?)': 1e-6
    }
}

WEIGHT_UNIT_MEASURE_PATTERN = {
    'en': {
        "(mega)?ton((ne)?s)?":1
    },
    'it': {
        "tonnellat[ae]":1,
        "quintal[ei]":0.1,
        "k(ilo)?g(ramm[oi])?|chil[oi]":1e-3
    },
    'es': {
        "tonelada(s)?":1,
        "quintal(es)?":0.1,
        "(chilo|kilo|k(iló)?)\s?g(ramo(s)?)?":1e-3
    }
}


def convert_cardinal_numbers(text: str, lan: str):
    new_text = []
    if lan == 'en':
        converter = worden2num
    elif lan == 'it':
        converter = wordit2num
    elif lan == 'es':
        converter = wordes2num
    tokens = text.split(' ')
    i = 0
    while i < len(tokens):
        word = tokens[i]
        number = converter(word.lower())
        if number is not None:
            parsed_number, words_to_skip = __convert_cardinal_iter(
                i, tokens, converter, number)
            new_text.append(str(parsed_number))
            i += words_to_skip
        else:
            new_text.append(word)
            i += 1
    return " ".join(new_text)

def __convert_cardinal_iter(start_idx: int, tokens: List, converter,
                            initial_number):
    n_words = 1
    parsed_number = initial_number
    for i in range(start_idx + 1, len(tokens)):
        new_number = converter(tokens[i].lower())
        if new_number is None: break
        number = converter(" ".join(tokens[start_idx:i + 1]).lower())
        if number is None: break
        n_words += 1
        parsed_number = number
    return parsed_number, n_words


def calculate_impact(sentence: str,
                         pos_word: int,
                         matching_word:str,
                         sentence_start: int,
                         impact_rule: RuleYara,
                         lan: str,
                         text: str = None):
    nums = list()  # collect all candidate estimates for matching keyword
    tokens = sentence.split(" ")
    word_pos = text[sentence_start:pos_word].count(' ')
    for idx, t in enumerate(tokens):
        if t.isdigit():
            pos_original = sentence_start + len(' '.join(tokens[:idx]))
            if idx != 0:
                pos_original += 1
            matches = impact_rule.apply_yara_rule(text=sentence,
                                           lan=lan,
                                           apply_lower=True,
                                           ignore_rules=['IsPluralWord'])
            if sum([
                    1 if re.search(r'\b' + t + r'\b', word) != None
                    and re.search(matching_word,word) == None else 0
                    for m in matches for word in m['word']
            ]) > 0:
                continue
            try:
                nums.append({
                    'value': int(t),
                    'pos': pos_original,
                    'distance': abs(idx - word_pos)
                })
            except ValueError as e:
                print(e)
                continue
    if len(nums) == 0:
        nums.append({'value': 0, 'pos': -1})
    return nums


def get_thousand_regex(lan: str):
    if lan == 'en':
        return "(?<=\d)([,])(?=\d{3})"
    else:
        return "(?<=\d)([.])(?=\d{3})"


def clean_text(text: str, nlp, lan: str):
    """
        Clean text removing hashtags, retweets, links, tags and non unicode characters and also replace cardinal words
    """
    # Remove puntuaction and not useful character
    # text =
    text = text.replace(u'\u2019', u'\'')
    text = re.sub(DELETE_PATTERN, " ", text)
    # text = text.encode('ascii','ignore')
    text = re.sub(HASHTAG_PATTERN, lambda m: m.group('entity'), text)
    text = re.sub(
        NUMBERS_PUNTUACTION, lambda m: f" {m.group('punt')} "
        if m.group('punt') is not None else f" {m.group('punt1')} ", text)
    text = re.sub(SENTENCE_PUNTUACTION, lambda m: f" {m.group('punt')} ", text)
    text = re.sub(get_thousand_regex(lan), "", text)
    text = convert_cardinal_numbers(text, lan)
    text = re.sub('\s{2,}', ' ', text)
    text = re.sub(RECONSTRUCT_PATTERN, lambda m: m.group('punt'),
                  text).strip().lower()
    doc = nlp(text)
    # Create dependency graph
    edges = []
    for token in doc:
        edges += [('{0}'.format(token.lower_), '{0}'.format(child.lower_))
                  for child in token.children]
        if token.pos_ == 'NUMERAL' or token.pos_ == 'VERB' or token.pos_ == 'AUX':
            edges += [('{0}'.format(child.lower_), '{0}'.format(token.lower_))
                      for child in token.children]
    graph = nx.DiGraph(edges)
    # Break text in sentences and remove named entities from each sentence
    entities_to_remove = [{
        'ent': ent.text,
        'start': ent.start_char
    } for ent in doc.ents if ent.label_ not in ['CARDINAL', 'QUANTITY']]
    sentences = []
    for sent in doc.sents:
        sent_text = sent.text
        for ent in [
                ent for ent in entities_to_remove
                if ent['start'] >= sent.start_char
                and ent['start'] < sent.end_char
        ]:
            sent_text = sent_text.replace(ent['ent'], 'X' * len(ent['ent']))
        sentences.append({
            'start': sent.start_char,
            'end': sent.end_char,
            'text': sent_text
        })
    return " ".join([s['text'] for s in sentences]), graph, sentences


def check_path(graph: nx.DiGraph, entity1: str, entity2: str):
    for ent1 in entity1.split(" "):
        for ent2 in entity2.split(" "):
            try:
                return nx.shortest_path_length(graph,
                                               source=ent1.lower(),
                                               target=ent2.lower())
            except (nx.NetworkXNoPath, nx.NodeNotFound) as e:
                if isinstance(e, nx.NodeNotFound): return None
                try:
                    return nx.shortest_path_length(graph,
                                                   source=ent2.lower(),
                                                   target=ent1.lower())
                except nx.NetworkXNoPath:
                    continue
    return None


def get_most_frequent(values: list):
    counts = {v: values.count(v) for v in set(values)}
    max_count = max(counts.values())
    return max([k for k, v in counts.items() if v == max_count])


def convert_measure(unit: str, value: int,lan:str,mapping:dict):
    for pattern, factor in mapping[lan].items():
        if re.search(pattern, unit) is None:
            continue
        else:
            return value * factor
    return factor


def combine_matches(lan: str, matches: list, tweet_graph: nx.DiGraph):
    result = {}
    used_pos = []
    matches = sorted(matches, key=lambda e: e['pos'])
    pos2value = {
        values['pos']: values['value']
        for m in matches for values in m['nums']
    }
    pos2value[-1] = 0
    for match in matches:
        if match['rule'] in unitary_rules:
            result[match['rule']] = {'word': match['word'], 'pos': -1}
            continue
        for num in sorted(match['nums'], key=lambda e: e['pos']):
            pos = num['pos']
            if pos in used_pos: continue
            # check current candidate is not after a following keyword
            if len([
                    m['rule'] for m in matches
                    if pos > m['pos'] and m['pos'] > match['pos']
            ]) > 0:
                continue
            # check current candidate is not before a preceding keyword
            if len([
                    m['rule'] for m in matches
                    if pos < m['pos'] and m['pos'] < match['pos']
            ]) > 0:
                continue
            # Check whether exist a path between word and values
            if pos != -1 and check_path(tweet_graph, match['word'],
                                        str(num['value'])) is None:
                continue
            if match['rule'] not in result:
                result[match['rule']] = {'word': match['word'], 'pos': pos}
                if pos != -1:
                    used_pos.append(pos)
            else:
                using_pos = [
                    k for k, v in pos2value.items()
                    if v == max(pos2value[result[match['rule']]['pos']],
                                pos2value[pos])
                ][0]
                result[match['rule']] = {
                    'word':
                    match['word']
                    if using_pos == pos else result[match['rule']]['word'],
                    'pos':
                    using_pos
                }
                if pos != -1:
                    used_pos.append(using_pos)
            break
        if match['rule'] not in result:
            result[match['rule']] = {'word': match['word'], 'pos': -1}
    final_result = {
        k: {
            'word': v['word'],
            'value': pos2value[v['pos']]
        }
        for k, v in result.items()
    }
    for rule, result in final_result.items():
        if rule == 'area':
            result['value'] = convert_measure(result['word'],
                                                result['value'],lan,AREA_UNIT_MEASURE_PATTERN)
        if rule == 'emission':
            result['value'] = convert_measure(result['word'],
                                                result['value'],lan,WEIGHT_UNIT_MEASURE_PATTERN)
    return final_result