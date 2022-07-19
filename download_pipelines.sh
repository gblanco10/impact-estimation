#!/bin/bash

python -m spacy download en_core_web_trf
python -m spacy download it_core_news_lg
python -m spacy download es_dep_news_trf

python -m nltk.downloader omw-1.4