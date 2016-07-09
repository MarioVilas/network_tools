#!/usr/bin/env python

import anyjson
import twitter
import zipfile

# Insert your API secrets here.
api = twitter.Api(
    consumer_key='INSERT HERE',
    consumer_secret='INSERT HERE',
    access_token_key='INSERT HERE',
    access_token_secret='INSERT HERE',
)

# Insert the name of the zip file with your Twitter archive here.
twitter_archive = 'twitter.zip'

# If you had to interrupt the script, just put the last
# status ID here and it will resume from that point on.
last = 0

def read_fake_json(zip, filename):
    data = zip.open(filename, 'rU').read()
    first_line, data = data.split("\n", 1)
    first_line = first_line.split("=", 1)[1]
    data = first_line + "\n" + data
    return anyjson.deserialize(data)

def parse_tweets_zipfile(filename):
    print "Parsing file: %s" % filename
    tweet_ids = {}
    with zipfile.ZipFile(filename, 'r') as zip:
        tweet_index = read_fake_json(zip, 'data/js/tweet_index.js')
        for item in tweet_index:
            tweets_this_month = read_fake_json(zip, item['file_name'])
            assert len(tweets_this_month) == item['tweet_count']
            tweet_ids["%d/%02d" % (item['year'], item['month'])] = [x['id'] for x in tweets_this_month]
    return tweet_ids

if __name__ == "__main__":
    begin = False
    tweet_ids = parse_tweets_zipfile(twitter_archive)
    for date in sorted(tweet_ids.keys(), reverse=True):
        year, month = date.split("/")
        if int(year) < 2016:
            print "Deleting tweets from: %s" % date
            for tid in tweet_ids[date]:
                if begin or last == 0 or tid == last:
                    begin = True
                    error_counter = 0
                    while True:
                        try:
                            api.DestroyStatus(tid)
                            print "%d: DELETED" % tid
                            break
                        except twitter.error.TwitterError, e:
                            try:
                                message = e.message[0]['message']
                                retry = False
                            except:
                                message = repr(e.message)
                                retry = True
                            print "%d: ERROR   %s" % (tid, message)
                            error_counter += 1
                            if error_counter > 5:
                                print "Too many errors, aborting!"
                                exit(1)
                            if not retry:
                                break
