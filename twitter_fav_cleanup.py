#!/usr/bin/env python

import os.path
import requests
import requests_oauthlib

CONSUMER_KEY = "INSERT HERE"
CONSUMER_SECRET = "INSERT HERE"

OAUTH_TOKEN = "INSERT HERE"
OAUTH_TOKEN_SECRET = "INSERT HERE"

if __name__ == "__main__":
    oauth = requests_oauthlib.OAuth1(CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=OAUTH_TOKEN,
            resource_owner_secret=OAUTH_TOKEN_SECRET)
    i = 0
    #i = 16
    while True:
        filename = "fav_%d.json" % i
        if os.path.exists(filename):
            print "%s already exists!" % filename
            break
        print filename
        r = requests.get(url="https://api.twitter.com/1.1/favorites/list.json?count=200", auth=oauth)
        with open(filename, "w") as fd:
            fd.write(r.text.encode("utf8"))
        fav_ids = [ fav['id'] for fav in r.json() ]
        if not fav_ids:
            break
        for fav in fav_ids:
            data = {'id' : fav}
            response = requests.post(url="https://api.twitter.com/1.1/favorites/destroy.json",
                            auth=oauth, data=data)
        i += 1

