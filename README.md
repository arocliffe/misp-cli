# misp-cli

A tool to check if an IOC (or a list of) exists in MISP

Dependancies can be installed with: `pip install -r requirements.txt`.

You must have the relevant MISP api keys saved into `~/.misp-cli.yaml` (see config's sample).

If supplying a list, IOC's must be presented in a txt file, one IOC per line.

## Usage:

```
usage: misp-cli.py [-h] [-e] [-v] [-f FILE] [-s SINGLE] [-m MISP]
                    [-event EVENT] [-o JINJA_STRING]

optional arguments:
  -h, --help       show this help message and exit
  -e               Show exact matches only i.e. searching for 'r.exe' will not
                   return 'rar.exe', 'spoolsvr.exe' etc. For use with SINGLE
                   IOC search only.
  -v               Verbose Mode
  -f FILE          Specify a list of IOCs to check
  -s SINGLE        Specify a single IOC to check
  -m MISP          Select MISP instance to search: misppriv (default),
                   barncat etc 
  -event EVENT     Select an event to query
  -o JINJA_STRING  jinja2 template string - use as following: "{{
                   event.attributes|selectattr("type", "equalto",
                   "md5")|join(", ", attribute="value")}}". Changing the
                   attribute selector where appropriate (type/to_ids/category
                   and associated flag). Available with single event
                   search and single attribute search. 
```
## Adding MISP instances

To add further MISP instances, simply add the URL, API key and SSL Cert path to the misp-cli.yaml file. Then pass as the -m argument.  

## Jinja2 Template usage

Quick tutorial on usage of Jinja2 templates in the context of misp-cli:

Using Jinja2 templates allow you to specify how you want the returned data displayed making it a very flexible solution.

So, as above, use the "-o" argument to set a Jinja2 string.
The template string itself must be present within single quotes - ' template goes here '.

To present a template for rendering, you must call the variable, in our case "event", followed by the attribute you want to access. This must be contained in double braces, as an expression.

So as an example:

```
$ python misp-cli.py -s "surprised.exe" -o '{{ event.id }} -  {{ event.title }}'
6626 -  Super bad malware
1942 -  Even more bad malwares 
51 -  This is not malware.....jks, of course it is
```
As you can see, calling event.id and event.title returned the Event ID and Title respectively, for each event that contained our string "surprised.exe".

The full list of attributes for the "event" variable are as follows:
- id = The Event ID in MISP
- title = The title of the MISP event
- creator = The email address of the creator of the Event
- published = Is the event published (returns boolean value)
- count = Returns the number of attributes within that event
- org = The organisation of the creator
- attributes = More on this to come....

So that's great, but what if you want to dig deeper into the attributes of each event? This is were we can expand "event.attributes"!

The "attributes" attribute (I know, sorry), contains several items, these are:
- value = The attribute/IOC value 
- type  = The type of the attribute, this is the same as MISP. Some example of "type" values include: md5, sha1, ip-dst, ip-src, email-src, domain, filename, url etc etc etc. 
- to_ids = Is the IDS flag set to Yes or No (This returns a boolean value)
- category = The category of the attribute/IOC, this is the same as MISP. Some example of "category" values include: "Payload Delivery", "Persistence mechanism", "Network activity", "Payload type" etc etc etc
- comments = The comment (if any) associated with that attribute/IOC

How do we incorporate this into our template? As follows!
```
$ python misp-cli.py -s "surprised.exe" -o '{{ event.id }} - {{ event.attributes||selectattr("#item", "equalto", "#value")|join(", ", attribute="value")}}'
```
Where #item is one of the items above (type, to_ids, category, etc) and #value is the corresponding value (for type, you could select: md5, filename, ip-dst, etc) and the "equalto" statement checks the items/values match, simple(ish)!

To put it all together in one example:
```
$ python misp-cli.py -s "surprised.exe" -o '{{ event.id }} - {{ event.attribute|selectattr("type", "equalto", "filename")|join(", ", attribute="value")}}'
6626  pleasantly surprised.exe, bad_malwares.exe, soopersafe.exe, totally_legit.zip, nothingtoseehere.dll. funny_catz.js, youtube_downloader.bat
```
As you can see in this example, we have displayed the event ID, followed by all attributes in that event that match "type" of "filename" and then displayed them on the same line using "join(", ", attribute="value")".

Give it a try!

NOTE - I have only tested this with python 2.7.13 so far

Improvements (in progress):
- Currently unable to handle URI's (will always return "Not Present" even when it is present)

## Credits

Airbus CERT
