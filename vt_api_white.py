'''
The MIT License (MIT)

Copyright (c) 2014 Patrick Olsen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Author: Patrick Olsen

This will parse the output from: md5deep.exe -z -r -l -o e -s "%SystemDrive%\*" > Hashes.txt

TODO:
[ ] - Add 60 second pause every 4 queries because of the VT API limit for public api keys.
'''
import sys, os
import argparse
import requests
import csv

def checkWhitelist(infile):
    remaining_hashes = {}
    for files in infile:
        file_size = files.strip().split("  ")[0].strip()
        file_hash = files.strip().split("  ")[1].strip()
        file_path = files.strip().split("  ")[2].strip()
        if len(file_hash) != 32:
            pass
        else:
            response = requests.get('<URL:PORT>/<PATH>/api/<VER>/hash/' + file_hash)
            json_response = response.json()
            if json_response['in_set'] == True:
                pass
            else:
                remaining_hashes[file_hash] = file_path, file_size
    return remaining_hashes

def vtResults(hash_remain, api_key):
    ''' key = MD5 Hash
        value[0] = File path
        value[1] = File size.'''
    vt_hits = {}
    for key, value in hash_remain.iteritems():
        params = {'apikey': api_key, 'resource': key}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        json_response = response.json()
        if json_response['response_code'] == 0:
            vt_hits[key] = value[0], value[1], "Not Scanned"
        elif json_response['response_code'] == 1:
            json_response['positives'] >= 0
            ratio = str(json_response['positives']) + "/" + str(json_response['total'])
            vt_hits[key] = value[0], value[1], str(ratio)

    return vt_hits

def outputResults(output):
    vtwriter = csv.writer(sys.stdout)
    vtwriter.writerow(['Hash', 'Filename', 'File Size', 'Ratio'])
    for key, value in output.iteritems():
        vtwriter.writerow([key, value[0], value[1], value[2]])

def main():
    parser = argparse.ArgumentParser(description='Look up hashes against a white list then look at VT.')
    parser.add_argument('-f', '--infile', help='Path to the input hashes.',required=True)
    parser.add_argument('-a', '--api', help='Virus Total API Key. If none submitted it will default to static.')
    args = parser.parse_args()
    if args.infile:
        infile = open(args.infile, 'r').readlines()
    else:
        print "You need to specify the hashes from your dump."
    if args.api:
        api_key = args.api
    else:
        api_key = '<ADD_API>'
    
    hash_remain = checkWhitelist(infile)
    output = vtResults(hash_remain, api_key)
    outputResults(output)

if __name__ == "__main__":
    main()
