import sys

def virusScan(fileName):
    import json, pprint, requests, time

    finished = 0
    pp = pprint.PrettyPrinter(indent=4)

    with open('api.ini', 'r') as myfile:
        apikey=myfile.read().replace('\n', '')
    headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "gzip,  My Python requests library example client or username"
      }
    paramsout = {'apikey': apikey}
    files = {'file': (fileName, open(fileName, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=paramsout)
    json_response = response.json()

    pp.pprint(json_response)

    print("\n\n")

    paramsin = {'apikey': apikey, 'resource': json_response["resource"]}
    while(finished == 0):
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=paramsin, headers=headers)
        json_response = response.json()
        if("total" in json_response):
            finished = 1
        else:
            time.sleep(30)

    pp.pprint(json_response)

dragNDrop = ''.join(sys.argv[1:2])

if dragNDrop == '':
    fileName = raw_input('''
Input the file with extension
>''')
else:
    fileOnly = dragNDrop.rfind('\\') + 1
    fileName = dragNDrop[fileOnly:]

virusScan(fileName)
