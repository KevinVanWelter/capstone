#! /bin/bash
cp /var/log/all-logs.log  all-messages.log
> /var/log/all-logs.log
python parse.py