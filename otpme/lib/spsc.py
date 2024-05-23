# -*- coding: utf-8 -*-
# Copyright (C) 2014 the2nd <the2nd@otpme.org>
import os
import re
import time
import gzip
import cchardet
import pprint
import datetime
#import codecs

try:
    if os.environ['OTPME_DEBUG_MODULE_LOADING'] == "True":
        print(_("Loading module: %s") % __name__)
except:
    pass

common_alt_chars = {
  'a': ['4', '@'],
  'b': ['8'],
  'c': ['(', '{', '[', '<'],
  'e': ['3'],
  'g': ['6', '9'],
  'i': ['1', '!', '|'],
  'l': ['1', '|', '7'],
  'o': ['0'],
  's': ['$', '5'],
  't': ['+', '7'],
  'x': ['%'],
  'z': ['2'],
}

def reverse_string(string):
    return string[::-1]

def calc_crack_times(combinations, pass_per_sec):
    """
    Calculate password crack times based on possible combinations and pass/sec.
    """
    crack_sec = int(combinations / pass_per_sec)
    crack_min = crack_sec / 60
    crack_hour = crack_min / 60
    crack_day = crack_hour / 24
    crack_year = crack_day / 365
    result = {
        'crack_sec'     : int(crack_sec),
        'crack_min'     : int(crack_min),
        'crack_hour'    : int(crack_hour),
        'crack_day'     : int(crack_day),
        'crack_year'    : int(crack_year),
        }
    return result

def calc_score(combinations, pass_per_sec, max_score=365):
    """ Calculate password score based on possible combinations and pass/sec. """
    result = calc_crack_times(combinations, pass_per_sec)
    crack_day = result['crack_day']
    if crack_day <= max_score:
        score = crack_day
    else:
        score = max_score
    result['score'] = score

    return result

def count_combinations(string):
    """ Calculate possible combinations of given string. """
    import string as _string
    valid_char_types = [
                    'numbers',
                    'ascii_lowercase',
                    'ascii_uppercase',
                    'chars_printable',
                    ]
    valid_characters = {
                'numbers'           : [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ],
                'ascii_uppercase'   : _string.ascii_uppercase,
                'ascii_lowercase'   : _string.ascii_lowercase,
                'chars_printable'   : _string.printable.replace("\n", ""),
                }

    char_types = []
    chars_count = 0
    for x in string:
        char_valid = False
        for char_type in valid_char_types:
            valid_chars = valid_characters[char_type]
            if x in valid_chars:
                if not char_type in char_types:
                    char_types.append(char_type)
                    chars_count += len(valid_chars)
                char_valid = True
                break
        if not char_valid:
            raise Exception("Invalid character in string.")

    string_len = len(string)
    combinations = chars_count**string_len
    return combinations

def to_alt(word):
    """ Translate word to alt. """
    import random
    new_word = ""
    for x in  word:
        if x.lower() in common_alt_chars:
            alt_chars = common_alt_chars[x.lower()]
            alt_chars_count = len(alt_chars)
            char_pos = random.randint(0,alt_chars_count-1)
            new_word = "%s%s" % (new_word,
                                common_alt_chars[x.lower()][char_pos])
        else:
            new_word = "%s%s" % (new_word, x)
    return new_word

def get_reverse_dict(org_dict):
    """ Build reversed dict. """
    new_dict = {}
    for key in org_dict:
        char_list = org_dict[key]
        for char in char_list:
            if not char in new_dict:
                new_dict[char] = []
            new_dict[char].append(key)
    return new_dict

def decode_alt_chars(word):
    """ Replace common alternative chars to get a possible 'normal' word. """
    char_dict = get_reverse_dict(common_alt_chars)
    words = []
    if word[0] in char_dict:
        words = list(char_dict[word[0]])
    else:
        words.append(word[0])
    for x in word[1:]:
        for word_part in list(words):
            words.remove(word_part)
            if x in char_dict:
                chars = list(char_dict[x])
                for c in chars:
                    new_word_part = "%s%s" % (word_part, c)
                    words.append(new_word_part)
            else:
                word_part = "%s%s" % (word_part, x)
                words.append(word_part)
    return words

def gen_slice_id(slice_chars):
    """ Gen slice ID. """
    x_list = []
    for x in slice_chars:
        x_list.append(str(x))
    slice_id = ":".join(x_list)
    return slice_id

def split_password(password, slice_len=3):
    """ Get all possible slices of the given password. """
    # FIXME: remove special chars from words to build a new one (e.g. Suz%i -> Suzi)
    pass_len = len(password)
    if pass_len == 0:
        raise Exception("Got empty password.")
    slices = {}
    while slice_len < pass_len:
        start_pos = 0
        end_pos = start_pos + slice_len
        while end_pos <= pass_len:
            pass_slice = password[start_pos:end_pos]
            slice_chars = list(range(start_pos, end_pos))
            slice_id = gen_slice_id(slice_chars)
            slices[slice_id] = {
                                'slice'         : pass_slice,
                                'alt_spells'    : [],
                                'slice_chars'   : slice_chars,
                                }
            # Add alt spelling only for slices with min length of 4.
            if len(pass_slice) >= 4:
                for alt_spell in decode_alt_chars(pass_slice):
                    if alt_spell != pass_slice:
                        if not alt_spell in slices[slice_id]['alt_spells']:
                            slices[slice_id]['alt_spells'].append(alt_spell)
            start_pos += 1
            end_pos += 1
        slice_len += 1

    # Add complete password with alt words.
    slice_chars = list(range(0, pass_len))
    slice_id = gen_slice_id(slice_chars)
    slices[slice_id] = {
                        'slice'         : password,
                        'alt_spells'    : [],
                        'slice_chars'   : slice_chars,
                        }
    for alt_spell in decode_alt_chars(password):
        if alt_spell != password:
            if not alt_spell in slices[slice_id]['alt_spells']:
                slices[slice_id]['alt_spells'].append(alt_spell)
    return slices

def check_common_spellings(word):
    """ Check for common spellings of words in passwords. """
    first_upper = False
    last_upper = False

    # If the word is complete lowercase no need for additional dict runs.
    if word.lower() == word:
        return 1

    # Check if only the first char is uppercase.
    if word[0] == word[0].upper():
        first_upper = True
        if word[1:] == word[1:].lower():
            return 2

    # Check if word is complete uppercase.
    if word.upper() == word:
        return 3

    # Check if only the last char is uppercase.
    if word[-1] == word[-1].upper():
        last_upper = True
        if word[:-1] == word[:-1].lower():
            return 4

    # Check if first and last char are uppercase.
    if first_upper and last_upper:
        if word[1:-1] == word[1:-1].lower():
            return 5

    # If the word does not match a common spelling but is not complete
    # lowercase calc the multiplier.
    word_without_numbers = re.sub("\d+", "", word)
    multiplier = 2**len(word_without_numbers)

    return multiplier

def check_repeats(word):
    """ Detect repeated chars. """
    rep = []
    # Some common used chars for repeats. (e.g. pwgen often uses [e,o])
    common_repeats_chars = '09abcdxyzoe.@-_'
    prev_char = word.lower()[0]
    for char in word.lower():
        if char != prev_char:
            return
        rep.append(char)
        prev_char = char

    if char.lower() in common_repeats_chars:
        char_comb = len(common_repeats_chars)
    else:
        char_comb = count_combinations(char)

    dict_size = (char_comb ** len(word)) * len(word)

    multiplier = check_common_spellings(word)
    dict_size = dict_size * multiplier

    result = {
        'word'              : word,
        'dict_type'         : 'list',
        'dict_name'         : 'repeat',
        'dict_size'         : dict_size,
        'score_multiplier'  : 0.3,
        }
    return result

def check_sequences(word):
    """ Detect sequences. """
    common_sequences = [
                    # Alphabet.
                    'abcdefghijklmnopqrstuvwxyz',
                    # Numbers.
                    '0123456789',
                    # German keyboard rows.
                    'qwertzuiop',
                    'asdfghjkl',
                    'yxcvbnm,.-',
                    # To be continued....
                    ]
    dict_size = 0
    word_len = len(word)
    sequence_found = False

    if word_len > 2:
        for sequence in common_sequences:
            dict_size += 1
            if word.lower() in sequence:
                sequence_found = True
                break
            dict_size += 1
            if word.lower() in reverse_string(sequence):
                sequence_found = True
                break

    if not sequence_found:
        if word_len > 4:
            slice_len = 2
            if word_len % 2 == 0:
                check_len = word_len
            else:
                check_len = word_len + 1
            if check_len >= word_len:
                check_len = word_len - 1
            while slice_len < check_len:
                start_pos = 0
                end_pos = start_pos + slice_len
                while end_pos <= check_len:
                    word_slice = word[start_pos:end_pos]
                    x = word.replace(word_slice, "")
                    if len(x) == 0:
                        sequence_found = True
                        for c in word:
                            dict_size += count_combinations(c)
                        dict_size = dict_size**(word_len/slice_len)
                    start_pos += 1
                    end_pos += 1
                slice_len += 1

    if not sequence_found:
        return None

    multiplier = check_common_spellings(word)
    dict_size = dict_size * multiplier

    result = {
        'word'              : word,
        'dict_type'         : 'list',
        'dict_name'         : 'sequence',
        'dict_size'         : dict_size,
        'score_multiplier'  : 0.3,
        }
    return result

#def get_match_combinations(matches, debug=False):
#    """ Get all possible match combinations without overlaps. """
#    # Credits: black_silence from #python.de@freenode.net
#    # https://piratenpad.de/p/pythonfun
#    combinations = []
#    overlap_groups = {}
#    overlap_lookup = {}
#
#    for key in matches:
#        item = matches[key]
#        if item['overlaps'] == []:
#            combinations.append(key)
#        else:
#            if key in overlap_lookup:
#                continue
#            overlap_groups[key] = item['overlaps']
#            overlap_groups[key].append(key)
#            overlap_lookup[key] = key
#            for overlap in item['overlaps']:
#                # Skip non-existing alternative. This may be the case for
#                # non_guessing_matches which does not include word guessing
#                # matches.
#                if not overlap in matches:
#                    continue
#                overlap_lookup[overlap] = key
#
#    combinations = [combinations]
#
#    if debug:
#        pprint.pprint(overlap_groups)
#
#    combinationStorage = []
#    stop_processing = False
#    for key in overlap_groups:
#        for alternative in overlap_groups[key]:
#            # Skip non-existing alternative. This may be the case for
#            # non_guessing_matches which does not include word guessing
#            # matches.
#            if not alternative in matches:
#                continue
#            for c in combinations:
#                skip = False
#                for x in c:
#                    for o in matches[x]['overlaps']:
#                        if alternative == o:
#                            skip = True
#                    if x in overlap_groups:
#                        if alternative in overlap_groups[x]:
#                            skip = True
#                if not skip:
#                    if alternative in c:
#                        continue
#                    t = [alternative]
#                    t.extend(c)
#                    combinationStorage.append(t)
#                    # For longer passwords we need to limit the combinations to
#                    # check because its to time consuming to check them all.
#                    if len(combinationStorage) > 5000:
#                        stop_processing = True
#                        break
#            if stop_processing:
#                break
#        combinations = combinationStorage
#        if stop_processing:
#            break
#
#    #print("%i combinations:" % len(combinations))
#    #pprint.pprint(combinations)
#
#    if debug:
#        for c in combinations:
#            for x in c:
#                print(matches[x]['word']),
#            print()
#
#    return combinations

def get_match_combinations(matches, debug=False):
    """ Get all possible match combinations without overlaps. """
    combinations = []

    # Get non-overlapping combinations.
    for slice_id in matches:
        c = [slice_id]
        for x in matches:
            skip = False
            x_overlaps = matches[x]['overlaps']
            for i in c:
                if i in x_overlaps:
                    skip = True
                    break
            if skip:
                continue
            if x in c:
                continue
            t = list(c)
            t.append(x)
            if sorted(t) in combinations:
                continue
            c.append(x)
        combinations.append(sorted(c))

    # Walk through all overlapping combinations and build all possible
    # combinations.
    while True:
        comb_len = len(combinations)
        for c in list(combinations):
            for x in c:
                # Skip non-existing matches. This may be the case for
                # non_guessing_matches which do not include word guessing.
                if not x in matches:
                    continue
                x_overlaps = matches[x]['overlaps']
                for o in x_overlaps:
                    # Skip non-existing matches. This may be the case for
                    # non_guessing_matches which do not include word guessing.
                    if not o in matches:
                        continue
                    o_overlaps = matches[o]['overlaps']
                    new_c = list(c)
                    if x in new_c:
                        new_c.remove(x)
                    for i in list(new_c):
                        if i in o_overlaps:
                            if i in new_c:
                                new_c.remove(i)
                    new_c.append(o)
                    if not sorted(new_c) in combinations:
                        combinations.append(sorted(new_c))
        # If nothing changed we got all combinations.
        if len(combinations) == comb_len:
            break
        # For longer passwords we need to limit the combinations to
        # check because its to time consuming to check all of them.
        if len(combinations) > 500:
            break

    # Remove small overlapping combinations.
    for c in list(combinations):
        for x in list(combinations):
            if c == x:
                continue
            if len(c) < len(x):
                shorter = list(c)
                longer = list(x)
            else:
                shorter = list(x)
                longer = list(c)
            overlaps = True
            for i in shorter:
                if not i in longer:
                    overlaps = False
                    break
            if overlaps:
                if shorter in combinations:
                    combinations.remove(shorter)

    if debug:
        for x in combinations:
            for slice_id in x:
                word = matches[slice_id]['word']
                print(word),
            print()

    return combinations

class SPSC(object):
    """ SPSC class to check password strength. """
    def __init__(self, dictionaries={}, dict_order=[],
        recent_years_past=150, recent_years_future=10,
        pass_per_sec=1000000):
        """ Init. """
        self.dictionaries = dictionaries
        if dictionaries and dict_order:
            self.dict_order = dict_order
        else:
            self.dict_order = list(dictionaries)
        # Recent years we will check for.
        self.recent_years_past = recent_years_past
        self.recent_years_future = recent_years_future
        self.recent_years = self.calc_recent_years()

        self.pass_per_sec = pass_per_sec
        self.pass_per_hour = pass_per_sec * 60 * 60

    def dump(self, dict_name):
        """ Dump dictionary words. """
        word_list = []
        sorted_dict = {}
        dictionary = self.dictionaries[dict_name]['dict']
        for x in dictionary:
            pos = dictionary[x]
            sorted_dict[pos] = x
        for x in sorted(sorted_dict):
            word = sorted_dict[x]
            word_list.append(word)
        return word_list

    def calc_recent_years(self):
        """ Calculate recent years. """
        current_year = datetime.datetime.now().year
        past_years = list(range(current_year-self.recent_years_past, current_year))
        future_years = list(range(current_year, current_year+self.recent_years_future))
        all_years = past_years + future_years
        recent_years = {}
        pos = 1
        for x in sorted(all_years):
            short_form = str(x)[-2:]
            recent_years[x] = pos
            pos += 1
            if int(short_form[0]) > 0:
                if not short_form in recent_years:
                    recent_years[short_form] = pos
                    pos += 1
        return recent_years

    def import_from_file(self, filename, dict_name,
        dict_type="list", min_word_len=2, progressbar=None):
        """ Import dictionary from file. """
        #fd = codecs.open(filename, 'r', 'utf8')
        dictionary = {}
        position = 0
        bytes_processed = 0

        if dict_name in self.dictionaries:
            dictionary = self.dictionaries[dict_name]['dict']
            dict_type = self.dictionaries[dict_name]['dict_type']
            position = len(dictionary)
        else:
            self.dict_order.append(dict_name)

        if filename.endswith(".gz"):
            fd = gzip.open(filename, "r")
        else:
            fd = open(filename, 'r')

        for line in fd:
            if progressbar:
                #bytes_processed += len(str(line))
                bytes_processed += len(line)
                progressbar.update(bytes_processed)
            if len(line) < min_word_len:
                continue
            word = line.replace(b"\n", b"").split()[0]
            if len(word) == 0:
                continue
            if len(word) < min_word_len:
                continue
            encoding = cchardet.detect(word)['encoding']
            try:
                word = word.decode(encoding)
            except:
                continue
            word = word.lower()
            if word in dictionary:
                continue
            position += 1
            #print("ADD:", position, word)
            dictionary[word] = position

        fd.close()

        if progressbar:
            progressbar.finish()

        self.dictionaries[dict_name] = {
                                    'dict'      : dictionary,
                                    'dict_type' : dict_type,
                                    }

    def check_word(self, word, alt_spell=False):
        """ Check word. """
        # Check word dicts.
        result = self.check_dictionaries(word)
        if result:
            return result
        # We do not check alternative spellings (leetspeak) for non-dicts.
        if alt_spell:
            return
        result = check_repeats(word)
        if result:
            return result
        result = check_sequences(word)
        if result:
            return result
        result = self.word_guessing(word)
        if result:
            return result
        return

    def get_score(self, password, debug=False):
        """ Calculate password strength score. """
        # For performance reasons we just check the first 32 chars of the
        # given password.
        password = password[0:32]
        # Start time.
        start_time = time.time()
        # Get possible password combinations without dictionary attacks etc.
        pass_comb = count_combinations(password)
        if debug:
            print("PASS_COMBINATIONS:", pass_comb)
        ## Return score if the password is crackable without dictionary within one
        ## year.
        ##crack_year = calc_crack_times(pass_comb, 1000000)['crack_year']
        # Calculate password score.
        pass_result = calc_score(pass_comb, self.pass_per_sec, max_score=365)
        pass_check_duration = time.time() - start_time
        pass_result['duration'] = pass_check_duration

        # Check password against common dictionaries, word guessing etc.
        all_matches, non_guessing_matches = self.get_matches(password)

        matches_list = []
        if len(non_guessing_matches) > 0:
            matches_list.append(non_guessing_matches)

        if len(all_matches) > 0:
            matches_list.append(all_matches)

        # Without matches return result of the password.
        if len(matches_list) == 0:
            return pass_result

        # We check non-guessing results first because word guessing results are
        # more time consuming.
        fastest_match = None
        fastest_matches = {}
        for matches in matches_list:
            # Get all possible match combinations.
            combinations = get_match_combinations(matches, debug=False)

            # Get fastest combination.
            fastest_comb = self.get_fastest_combination(password,
                                                        matches,
                                                        combinations)
            found_faster_match = False
            dict_comb = fastest_comb['combinations']
            if fastest_match is None:
                found_faster_match = True
            elif dict_comb < fastest_match:
                found_faster_match = True
            if found_faster_match:
                fastest_match = dict_comb
                fastest_matches[dict_comb] = fastest_comb
                continue

        # Calculate password strength score.
        result = calc_score(dict_comb, self.pass_per_sec, max_score=365)
        score = result['score']
        match_count = fastest_comb['match_count']
        x_slices = fastest_comb['slices']
        for x_sclice in x_slices:
            score_multiplier = x_slices[x_sclice]['score_multiplier']
            x_score = score / match_count
            score = x_score * score_multiplier
            score = int(score + (x_score * (match_count - 1)))
        # Update score.
        result['score'] = score
        # Add matches to result.
        result['match_result'] = fastest_comb

        # If cracking using dictionaries is slower return normal crack time.
        if pass_comb < dict_comb:
            return pass_result

        match_check_duration = time.time() - start_time
        result['duration'] = match_check_duration

        if debug:
            pprint.pprint(result)

        return result

    def word_guessing(self, word):
        """ Try to guess a word based on its start/middle/end characters. """
        ascii_re = re.compile('^[a-zA-Z]*$')
        if not ascii_re.match(word):
            return
        for dict_name in self.dict_order:
            dict_type = self.dictionaries[dict_name]['dict_type']
            if dict_type != "guessing":
                continue
            dictionary = self.dictionaries[dict_name]['dict']

            start = "%s:" % word[0:3]
            middle = word[3:-3]
            end = ":%s" % word[-3:]
            found_start = False
            found_middle = []
            found_end = False
            if len(middle) >= 3:
                middle_slices = split_password(middle, slice_len=3)
                for s in middle_slices:
                    if len(middle_slices[s]['slice']) != 3:
                        continue
                    neg_middle_slice = "-%s-" % middle_slices[s]['slice']
                    #print("JOOOOO", word, middle, neg_middle_slice)
                    if neg_middle_slice.lower() in dictionary:
                        found_middle = []
                        break
                    middle_slice = ":%s:" % middle_slices[s]['slice']
                    if middle_slice.lower() in dictionary:
                        found_middle.append(middle_slice)
            else:
                if len(word) >= 6:
                    found_middle = [ 'dummy' ]

            if len(found_middle) >= 1:
                score_multiplier = 0.2
                if len(found_middle) >= 3:
                    score_multiplier = 0.1
                if start.lower() in dictionary:
                    found_start = True
                if end.lower() in dictionary:
                    found_end = True

            if not found_start:
                continue
            if not found_middle:
                continue
            if not found_end:
                continue

            # We use a low fake dict size for word guessing results because
            # there is no way to calculate a realistic dict size and we want
            # to prevent users from using words in their passwords.
            #dict_size = 10000
            dict_size = len(dictionary)
            result = {
                'word'              : word,
                'dict_type'         : dict_type,
                'dict_name'         : dict_name,
                'dict_size'         : dict_size,
                'score_multiplier'  : score_multiplier,
                }
            #print("JOOOOOOOOOOO", word)
            #pprint.pprint(result)
            return result

        return False

    def check_dictionaries(self, word):
        """ Check if word is in any dictionary. """
        dict_size = 0
        # Check if word is a number. This is useful because we get a password
        # split by characters and numbers. This way we can easier check for
        # word start/end (e.g. word_guessing() -> found_start, found_end).
        try:
            number = int(word)
        except:
            number = False
        if number is not False:
            # Check recent years.
            if number in self.recent_years:
                score_multiplier = 0.1
                dict_name = "recent_years"
                dict_size = self.recent_years[number]
            else:
                score_multiplier = 1.3
                dict_name = "numbers"
                x_number = ""
                for x in range(0, len(word)):
                    x_number += "9"
                dict_size = int(x_number)
            result = {
                'word'              : number,
                'dict_type'         : 'list',
                'dict_name'         : dict_name,
                'dict_size'         : dict_size,
                'score_multiplier'  : score_multiplier,
                }
            return result

        # Check dicts.
        for dict_name in self.dict_order:
            dict_type = self.dictionaries[dict_name]['dict_type']
            if dict_type != "list" and dict_type != "sorted-list":
                continue
            dictionary = self.dictionaries[dict_name]['dict']
            if word.lower() in dictionary:
                if dict_type == "sorted-list":
                    dict_size = dictionary[word.lower()]
                    multiplier = check_common_spellings(word)
                    dict_size = dict_size * multiplier
                else:
                    # For non-sorted dicts we limit the dict size to 10000 to
                    # prevent high scores even if the password includes a word.
                    dict_size = 10000
                result = {
                    'word'              : word,
                    'dict_type'         : dict_type,
                    'dict_name'         : dict_name,
                    'dict_size'         : dict_size,
                    'score_multiplier'  : 0.1,
                    }
                return result

        return False

    def get_matches(self, password):
        """ Check password for common words, years etc. """
        # Split password in slices.
        all_slices = split_password(password, slice_len=2)

        # Sort slices by length. Longest first (e.g. check complete password first).
        all_words_sorted = []
        sort_dict = {}
        for slice_id in all_slices:
            pass_slice = all_slices[slice_id]['slice']
            slice_len = len(pass_slice)
            if not slice_len in sort_dict:
                sort_dict[slice_len] = []
            sort_dict[slice_len].append([slice_id, pass_slice])

        for x in sorted(sort_dict, reverse=True):
            for a in sort_dict[x]:
                slice_id = a[0]
                pass_slice = a[1]
                all_words_sorted.append(slice_id)

        # Walk through all slices...
        non_guessing_matches = {}
        all_matches = {}
        match_chars = {}
        whole_word_match = False
        for slice_id in all_words_sorted:
            if whole_word_match:
                break
            # Get original slice. (e.g. "Password")
            pass_slice = all_slices[slice_id]['slice']
            # Get slice alt spellings (e.g. "P@ssword"
            alt_spells = all_slices[slice_id]['alt_spells']
            # Get slice character positions. (e.g. "1:2:3" -> "@ss")
            slice_chars = all_slices[slice_id]['slice_chars']
            # Build list with all spellings, original first.
            all_spells_list = [pass_slice]
            all_spells_list += list(alt_spells)
            for x in all_spells_list:
                # Skip already processed slices.
                if slice_id in all_matches:
                    continue
                # Check if the current result is a result of an alternative
                # spelling.
                if x in alt_spells:
                    alt_spell = True
                else:
                    alt_spell = False

                # Check if slice matches some common stuff (e.g. word dictionaries)
                result = self.check_word(x, alt_spell=alt_spell)
                if not result:
                    continue
                word = result['word']
                dict_type = result['dict_type']

                # Build match entry or use existing.
                if slice_id in all_matches:
                    match_entry = all_matches[slice_id]
                    overlaps = match_entry['overlaps']
                    word_matches = match_entry['word_matches']
                else:
                    overlaps = []
                    word_matches = {}
                    match_entry = {
                            'word'          : word,
                            'slice'         : pass_slice,
                            'word_matches'  : word_matches,
                            'overlaps'      : overlaps,
                            }
                    all_matches[slice_id] = match_entry

                # Build list with overlapping slices.
                for c in slice_chars:
                    if c in match_chars:
                        for o in match_chars[c]:
                            if o == slice_id:
                                continue
                            if not o in overlaps:
                                overlaps.append(str(o))
                                o_overlaps = all_matches[o]['overlaps']
                                if not slice_id in o_overlaps:
                                    o_overlaps.append(str(slice_id))
                        match_chars[c].append(slice_id)
                    else:
                        match_chars[c] = [slice_id]

                # Add entry for the current result. There might be more than
                # one result per word.
                word_entry = {
                        'dict_name'         : result['dict_name'],
                        'dict_type'         : result['dict_type'],
                        'dict_size'         : result['dict_size'],
                        'alt_spell'         : alt_spell,
                        'score_multiplier'  : result['score_multiplier'],
                        }
                word_matches[pass_slice] = word_entry

                if dict_type != "guessing":
                    non_guessing_matches[slice_id] = match_entry

                if word == password:
                    whole_word_match = True
                    break

        return all_matches, non_guessing_matches

    def get_fastest_combination(self, password, matches, combinations):
        """ Get the fastest match combination. """
        # Get fastest combination.
        fastest_comb = None
        smalles_comb = None
        for c in combinations:
            comb = {}
            for slice_id in c:
                comb[slice_id] = matches[slice_id]
                word = matches[slice_id]['word']
                word_matches = matches[slice_id]['word_matches']
                for match_string in word_matches:
                    dict_size = word_matches[match_string]['dict_size']
                    dict_name = word_matches[match_string]['dict_name']
                    dict_type = word_matches[match_string]['dict_type']
                    alt_spell = word_matches[match_string]['alt_spell']
                    score_multiplier = word_matches[match_string]['score_multiplier']
                    #print(match_string, word, alt_spell)

                comb[slice_id] = {
                                'word'              : word,
                                'slice'             : match_string,
                                'dict_name'         : dict_name,
                                'dict_type'         : dict_type,
                                'dict_size'         : dict_size,
                                'alt_spell'         : alt_spell,
                                'score_multiplier'  : score_multiplier,
                                }

            # Get all characters that are covered by a match.
            match_chars = []
            for slice_id in comb:
                match_string = comb[slice_id]['slice']
                match_chars += slice_id.split(":")

            # Get remaining chars of the password (not covered by a match).
            pass_test_string = ""
            char_count = 0
            for x in password:
                if not str(char_count) in match_chars:
                    pass_test_string += x
                char_count += 1

            # Count found matches.
            match_count = len(comb)
            split_size = match_count

            # Count dictionary entries of this combination.
            dict_entries = 0
            processed_dicts = []
            for slice_id in comb:
                dict_name = comb[slice_id]['dict_name']
                if dict_name in processed_dicts:
                    continue
                processed_dicts.append(dict_name)
                dict_size = comb[slice_id]['dict_size']
                dict_entries += dict_size

            # Count possible combinations per remaining password character.
            non_match_combinations = 0
            if len(pass_test_string) > 0:
                for x in pass_test_string:
                    non_match_combinations += count_combinations(x)
                    split_size += 1

            # Calculate possible combinations.
            combined_combinations = (dict_entries + non_match_combinations)**split_size

            # Check if the current combination is faster/smaller than the previous
            # selected fastest/smallest.
            if not smalles_comb or combined_combinations < smalles_comb:
                fastest_comb = {
                            'slices'        : comb,
                            'dict_len'      : dict_entries,
                            'match_count'   : match_count,
                            'non_match_str' : pass_test_string,
                            'non_match_len' : len(pass_test_string),
                            'non_match_comb': non_match_combinations,
                            'combinations'  : combined_combinations,
                        }
                smalles_comb = combined_combinations

        return fastest_comb
