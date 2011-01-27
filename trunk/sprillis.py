 #/usr/bin/python
import re, sys, os
 
print 'PHP source vulnerability scanner.'
print 'Coded by Starwiz.'
print 'Greets to http://www.doxsters.net and http://greyhat-security.com\n'
 
LFIRFIex1 = re.compile('(\\$_REQUEST\\[.*?\\] = \'(?:[a-z][a-z0-9_]*)\\.php\')', re.IGNORECASE|re.DOTALL)
LFIRFIex2 = re.compile('(\\$_GET\\[.*?\\] = \'(?:[a-z][a-z0-9_]*)\\.php\')', re.IGNORECASE|re.DOTALL)
PHPex = re.compile('((?:[a-z][a-z0-9_]*)\\.php)', re.IGNORECASE|re.DOTALL)
CodeINJex1 = re.compile('(eval\\(".*?"\\))', re.IGNORECASE|re.DOTALL)
CodeINJex1_2 = re.compile('( = )', re.IGNORECASE|re.DOTALL)
CodeINJex2 = re.compile('(system\\(".*?"\\);)', re.IGNORECASE|re.DOTALL)
Requestex1 = re.compile('(\\$_GET\\[\\\'.*?\\\'\\])', re.IGNORECASE|re.DOTALL)
Requestex2 = re.compile('(\\$_REQUEST\\[\\\'.*?\\\'\\])', re.IGNORECASE|re.DOTALL)
InputFilterex = re.compile('((preg_match\\(".*?")).*?(\\))', re.IGNORECASE|re.DOTALL)
LRFIcookex = re.compile('(.(?:[a-z][a-z0-9_]*) = \\$_COOKIE\\[\\\'.*?\\\'\\])', re.IGNORECASE|re.DOTALL)
 
re1='(eval)'	# Variable Name 1
re2='(\\()'	# Any Single Character 1
re3='(".*?")'	# Double Quote String 1
re4='(\\))'	# Any Single Character 2
 
 
fs = []
pes = []
lrfinum = []
phpnum = []
phps = []
phpexs = []
codeinj = []
citemp = []
totalreq = []
inpfilter = []
lrficook = []
iio = 0
 
def usage():
    print 'Usage \t\t' + sys.argv[0] + ' directory of php file(s)'
    print 'Example \t' + sys.argv[0] + ' ' + os.getcwd()
    sys.exit()
    
 
def numFiles():
    for dir, sf, files in os.walk(sys.argv[1]):
        for item in files:
            ldld = dir + '/' + item
            ldld = ''.join(ldld)
            fs.append(ldld)
    print str(len(fs)) + ' files.'
 
 
def numPHP():
    for item in fs:
        temp = []
        temp2 = []
        temp = list(item)
        temp2.append(temp[-1])
        temp2.append(temp[-2])
        temp2.append(temp[-3])
        temp2 = ''.join(temp2)
        if temp2 == 'php':
            phps.append(item)
    print str(len(phps)) + ' php files.'
    
    
def PHPcheck():
    for item in phps:
        rs = []
        lol = open(item, 'r').read()
        rs = PHPex.findall(lol)
        if len(rs) != 0:
            for i in rs:
                phpnum.append(str(i) + ' - string "php" was mentioned in ' + str(item))
    print str(len(phpnum)) + ' times "PHP" was mentioned.'
    
 
def RequestNums():
    for item in phps:
        rs = []
        lol = open(item, 'r').read()
        rs = Requestex1.findall(lol)
        if len(rs) != 0:
            for i in rs:
                totalreq.append(str(i) + ' - request is taken in ' + str(item))
        rs = []
        rs = Requestex2.findall(lol)
        if len(rs) != 0:
            for i in rs:
                totalreq.append(str(i) + ' - request is taken in ' + str(item))
    print str(len(totalreq)) + ' requests the server takes.'
    
 
def InputFilter():
    for item in phps:
        rs = []
        lol = open(item, 'r').read()
        rs = InputFilterex.findall(lol)
        if len(rs) != 0:
            for i in rs:
                inpfilter.append(str(i) + ' - input filter in ' + str(item))
    print str(len(inpfilter)) + ' times input was called to a filter.'
 
 
def RLFIcheck():
    for item in phps:
        rs = []
        lol = open(item, 'r').read()
        rs = LFIRFIex1.findall(lol)
        if len(rs) != 0:
            for i in rs:
                lrfinum.append(str(i) + ' - possible LFI/RFI vuln in ' + str(item))
        rs = []
        re = LFIRFIex2.findall(lol)
        if len(rs) !=0:
            for i in rs:
                lrfinum.append(str(i) + ' - possible LFI/RFI vuln in ' + str(item))
    print str(len(lrfinum)) + ' possible RFI/LFI vulnerabilities.'
 
 
def CodeINJcheck():
    global citemp
    for item in phps:
        rs = []
        lol = open(item, 'r').read()
        rs = CodeINJex1.findall(lol)
        if len(rs) != 0:
            for i in rs:
                citemp.append(str(i))
        rs = []
        if len(citemp) != 0:
            for i in citemp:
                rs = []
                rs = CodeINJex1_2.findall(i)
                if len(rs) != 0:
                    codeinj.append(str(i) + ' - possible code injection vuln in ' + str(item))
        rs = []
        citemp = []
        rs = CodeINJex2.findall(lol)
        if len(rs) != 0:
            for i in rs:
                codeinj.append(str(i) + ' - possible code injection vuln in ' + str(item))
    print str(len(codeinj)) + ' possible code injection vulnerabilities.'
 
 
def LRFIcook():
    for item in phps:
        rs = []
        lol = open(item, 'r').read()
        rs = LRFIcookex.findall(lol)
        if len(rs) != 0:
            for i in rs:
                lrficook.append(str(i) + ' - possible path traversal using the cookie vuln in ' + str(item))
    print str(len(lrficook)) + ' possible RFI/LFI vulns using cookies.'
 
 
 
if len(sys.argv) != 2:
    if len(sys.argv) != 3:
        usage()
 
 
if len(sys.argv) == 3:
    iio = sys.argv[2]
 
numFiles()
numPHP()
RLFIcheck()
LRFIcook()
CodeINJcheck()
print ''
PHPcheck()
RequestNums()
InputFilter()
 
for item in lrfinum:
    pes.append(item)
for item in codeinj:
    pes.append(item)
for item in lrficook:
    pes.append(item)
 
if iio == 1:
    for item in phpnum:
        pes.append(item)
    for item in totalreq:
        pes.append(item)
    for item in inpfilter:
        pes.append(item)
 
if len(pes) != 0:
    pe = open('possible.txt', 'w')
    pe.write("If you don't know how to exploit these, check http://www.owasp.org/index.php/Category:Attack\n\n")
    for item in pes:
        pe.write(str(item) + '\n')
    pe.close()
 
print '\nCheck possible.txt for output'
print 'Please keep in mind this is an alpha and I\'m still working on it.'
