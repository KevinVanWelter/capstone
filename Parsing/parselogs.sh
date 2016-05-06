#! /bin/bash
cp /var/log/all-logs.log  ../stuff/all-messages.log
> /var/log/all-logs.log
rm -rf ../Parsing/ParsedLogs/*
python ../Parsing/betterParsing.py