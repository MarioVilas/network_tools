#!/usr/bin/env python

# XKCD password generator

import argparse
import collections
import os.path
import random

# Parse the command line options.
parser = argparse.ArgumentParser(description="XKCD password generator https://xkcd.com/936/")
parser.add_argument("-d", "--dictionary", default="en", help="Dictionary to use")
parser.add_argument("--min-words", type=int, default=4, help="Minimum number of words to use")
parser.add_argument("--max-words", type=int, default=4, help="Maximum number of words to use")
parser.add_argument("--min-length", type=int, default=4, help="Minimum length of the words to use")
parser.add_argument("--max-length", type=int, default=8, help="Maximum length of the words to use")
args = parser.parse_args()
if not os.path.exists(args.dictionary):
    if not "." in args.dictionary:
        args.dictionary = args.dictionary + ".txt"
    if not os.path.exists(args.dictionary):
        if not os.path.sep in args.dictionary:
            args.dictionary = os.path.abspath(os.path.join(os.path.dirname(__file__), args.dictionary))
        if not os.path.exists(args.dictionary):
            parser.error("Could not find dictionary: %s" % args.dictionary)
print args

# Load the dictionary, skipping words of the wrong length.
min_length = args.min_length
max_length = args.max_length
dictionary = collections.defaultdict(list)
with open(args.dictionary, "rU") as fd:
    for line in fd:
        for word in line.strip().split(" "):
            word = word.strip().lower()
            if "'" in word:
                continue
            length = len(word)
            if min_length <= length <= max_length:
                dictionary[length].append(word)

# Pick the random words for the password.
words = []
lengths = dictionary.keys()
lengths.sort()
count = random.randint(args.min_words, args.max_words)
while count > 0:
    length = random.choice(lengths)
    word = random.choice(dictionary[length])
    words.append(word)
    count = count - 1

# Print out the chosen password.
print " ".join(words)

