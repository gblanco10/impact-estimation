import re
from word2numberi18n import w2n
from spa2num.converter import to_number as es2number
from pattern.text.en import singularize as en_singularize
from pattern.text.es import singularize as es_singularize

en_instance = w2n.W2N(lang_param="en")


NUMBERS_SEQ = (
    ('dieci', '10'),
    ('undici', '11'),
    ('dodici', '12'),('dozzina', '12'),('dozzine', '12'),
    ('tredici', '13'),
    ('quattordici', '14'),
    ('quindici', '15'),
    ('sedici', '16'),
    ('diciasette', '17'),
    ('diciotto', '18'),
    ('diciannove', '19'),
    ('venti','20'),
    ('ventuno','21'),
    ('ventotto','28'),
    ('trenta', '30'),
    ('trentuno', '31'),
    ('trentotto', '38'),
    ('quaranta', '40'),
    ('quarantuno', '41'),
    ('quarantotto', '48'),
    ('cinquanta', '50'),
    ('cinquantuno', '51'),
    ('cinquantotto', '58'),
    ('sessanta', '60'),
    ('sessantuno', '61'),
    ('sessantotto', '68'),
    ('settanta', '70'),
    ('settantuno', '71'),
    ('settantotto', '78'),
    ('ottanta', '80'),
    ('ottantuno', '81'),
    ('ottantotto', '88'),
    ('novanta', '90'),
    ('novantuno', '91'),
    ('novantotto', '98'),
    ('cento', '100'),('centinaia','100'),
    ('mille', '1000'), ('mila', '1000'), ('migliaia', '1000'),
    ('milione', '1000000'), ('milioni', '1000000'),
    ('miliardo', '1000000000'), ('miliardi', '1000000000'),
    ('uno', '1'), ('una','1'),('un', '1'),
    ('due', '2'),
    ('tre', '3'),
    ('quattro', '4'),
    ('cinque', '5'),
    ('sei', '6'),
    ('sette', '7'),
    ('otto', '8'),
    ('nove', '9'),
    )

NUMBERS = dict(NUMBERS_SEQ)

TOKEN_REGEX = re.compile('|'.join('(%s)' % num for num, val in NUMBERS_SEQ))


def worden2num(word):
    if word in ['a']:
        return None
    try:
        num = int(en_instance.word_to_num(en_singularize(word)))
        return num
    except :
        try:
            num = int(en_instance.word_to_num(word))
            return num
        except :
            return None
                
def wordit2num(word):
    try:
        num = int(let2num(word.strip()))
        return num
    except ValueError:
        return None

def wordes2num(word):
    if word in ['y',' ','','es']: return None
    try:
        num = int(es2number(es_singularize(word)))
        return num
    except ValueError:
        try:
            num = int(es2number(word))
            return num
        except ValueError:
            return None

def let2num(num_repr):
    '''Yield the numeric representation of *num_repr*.'''

    num_repr = num_repr.lower()
    result = 0
    accumulator = 0

    for token in (tok for tok in TOKEN_REGEX.split(num_repr) if tok):
        try:
            value = float(NUMBERS[token])
        except KeyError:
            try :
                value = float(token.strip())
            except ValueError:
                if (result > 0 or accumulator > 0) and (token == ' ' or token.strip() == 'di'):
                    continue
                raise ValueError
        if token in ('miliardo','miliardi','milioni','milione','mille','migliaia','mila'):
            accumulator=accumulator*value if accumulator > 0 else value
            result+=accumulator
            accumulator=0
        elif token in ('cento','centinaia'):
            accumulator=accumulator*value if accumulator > 0 else value
        else:
            accumulator+=value
    result = int(result+accumulator)
    if result > 0:
        return result
    else:
        return 'None'
