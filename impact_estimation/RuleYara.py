import yara
import re


class RuleYara:

    def __init__(self, name: str, rule_names: list):
        """
        Creates a Yara Rule object
        :param rule_names: list or rule names to detect
        :param name: name of the object
        """
        self.name = name
        self.rules = dict()
        self.rule_names = rule_names

    def add_rule(self, rule_filepath: str, lan: str):
        """
        Add a specific yara rule described in file to the object
        It is possible specify lan = 'all' to define rules valid for each language
        :param rule_filepath: path to the yara file
        :param lan: str, define the rule language, for generic language specify 'all'
        """
        if lan not in self.rules:
            self.rules[lan] = list()
        self.rules[lan].append(yara.compile(filepath=rule_filepath))

    def modify_rules_names(self, names: list):
        self.rule_names = names

    def apply_yara_rule(self, text: str, lan: str,
                        apply_lower: bool = True,
                        ignore_rules: list = None,
                        select_rules: list = None):
        """
        Apply rule to the text
        :param text: A string can be a full text or simply a word.
        :param lan: str indicating tweet language
        :param apply_lower: boolean to indicate if text need to be in lower case before apply rule.
        :param ignore_rules: optional, a list of rule name to ignore
        :param select_rules: optional, a list of rule name we want to select
        If not specified will be retrieve all rules matching with self.names except ignore_rules (if specified)
        :return: a list of {'word': , 'rule': } matched in text by the rule
        """

        result = list()
        if apply_lower:
            text = text.lower()
        select_rules = select_rules if select_rules is not None else self.rule_names

        # include rules 'all' common to all languages
        rules = self.rules[lan] + (self.rules['all'] if 'all' in self.rules else [])

        for r in rules:
            matches = r.match(data=text)
            if len(matches) > 0:
                for match in matches:
                    if 'name' not in match.meta:
                        raise Exception("A Yara Rule requires a field name in its meta definition")
                    rule_name = match.meta['name']
                    if rule_name not in select_rules:
                        continue
                    if (ignore_rules is not None) and (rule_name in ignore_rules):
                        continue
                    try:
                        words_found = list()
                        pos_found = list()
                        if len(match.tags) > 0 and match.tags[0] == 'Max':
                            # Only word with max index must be retrieved
                            words_ids = [int(re.findall("\d+",item[1])[0]) for item in match.strings]
                            word_ixs = [i for i,w_id in enumerate(words_ids) if w_id == max(words_ids)]
                            string_items=[match.strings[ix] for ix in word_ixs]
                        else:
                            string_items = match.strings
                        for item in string_items:
                            word = item[-1].decode("utf-8")
                            words_found.append(word)
                            pos_found.append(item[0] if item[0] < len(text) else item[0] - len(word) )
                        result.append({'word': words_found, 'rule': rule_name, 'pos': pos_found})
                    except :
                        continue

        return result
