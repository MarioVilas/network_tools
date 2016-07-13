#!/bin/bash

# Convert Aspell dictionaries to wordlists.

LANGUAGES="af ar bg bn br ca cs cy da de el en es fi fo fr ga gd gl gu he hi hr id is it la ml mr nb nl or pa pl pt_BR pt_PT ru sk sl sr sv ta te"

for LANG in $LANGUAGES
do
    aspell -d $LANG --encoding=utf-8 dump master | aspell -l $LANG --encoding=utf-8 expand | sort > $LANG.txt
done
