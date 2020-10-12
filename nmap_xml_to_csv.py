
__description__ = 'nmap xml script output parser'
__author__ = 'Didier Stevens, modify by Sumedt Jitpukdebodin, and additionaly modified by ezno'
__version__ = '1.0 KFISAC'
__date__ = '2015/10/15'

import optparse
import xml.dom.minidom
import glob
import collections

QUOTE = '"'

def ToString(value):
    if type(value) == type(''):
        return value
    else:
        return str(value)

def Quote(value, separator, quote):
    value = ToString(value)
    if separator in value:
        return quote + value + quote
    else:
        return value

def MakeCSVLine(row, separator, quote):
    return separator.join([Quote(value, separator, quote) for value in row])

class cOutput():
    def __init__(self, filename=None):
        self.filename = filename
        if self.filename and self.filename != '':
            self.f = open(self.filename, 'w')
        else:
            self.f = None

    def Line(self, line):
        if self.f:
            self.f.write(line + '\n')
        else:
            print(line)

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None

class cOutputCSV():
    def __init__(self, options):
        if options.output:
            self.oOutput = cOutput(options.output)
        else:
            self.oOutput = cOutput()
        self.options = options

    def Row(self, row):
        self.oOutput.Line(MakeCSVLine(row, self.options.separator, QUOTE))

    def Close(self):
        self.oOutput.Close()

# function for `Nessus Plugin ID` match, find case and add 'Plugin ID' value in the CSV row
# return value : Nessus Plugin ID
def getNessusPluginID(resultRow):
    NessusPluginID = 'None'
    portN = resultRow[1]
    protocolType = resultRow[2]
    state = resultRow[3]
    serviceNm = resultRow[4]
    scriptNm = ''
    found_flag = False
    
    # get NSE script result and match to 'NessusPlugin ID'
    if len(resultRow) > 5 :
        scriptNm = resultRow[5]
        if scriptNm == 'http-trace' :
        # http-trace,	HTTP TRACE 탐색에 사용됨. 웹 포트만 대상으로 함	"BBA-014	웹 서버 HTTP Trace 기능 지원"
            NessusPluginID = '11213'
            found_flag = True
        if scriptNm == 'ftp-anon' :
        # ftp-anon,	FTP server 에서 anonymous 허용	"BAC-005	Anonymous FTP 비활성화"
            NessusPluginID = '10079'
            found_flag = True
        if scriptNm == 'smtp-enum-users' :
        # smtp-enum-users,	SMTP 서비스 확인 및 추가정보 수집	BAB-002 SMTP 서비스 expn/vrfy 명령어 실행
            NessusPluginID = '10263'
            found_flag = True
        if scriptNm == 'rpcinfo' :
        # rpcinfo,   RPC 관련 서비스 및 추가정보 수집    BAC-009 불필요한 RPC서비스 실행
            NessusPluginID = '10227'
            found_flag = True
        if scriptNm == 'smtp-open-relay' :
        # smtp-open-relay,   다른 메일 서버가 보낸 메일을 다시 발송하는 relay 기능을 제공   BAB-008  스팸 메일 릴레이 제한
            NessusPluginID = '10262'
            found_flag = True
        if scriptNm == 'dns-recursion' :
        # dns-recursion,   DNS recursion 여부 확인  BBC-003  DNS 서버 Recursive Query 허용
            NessusPluginID = '10539'
            found_flag = True
        if scriptNm == 'finger' :
        # finger,   finger 서비스 확인 및 추가정보 수집  BAE-002 Finger 서비스 비활성화
            NessusPluginID = '10068'
            found_flag = True
        if scriptNm == 'daytime' :
        # daytime   daytime 서비스 확인 및 추가정보 수집 BAE-010 DoS 공격에 취약한 서비스 비활성화
            NessusPluginID = '10457'
            found_flag = True
        if scriptNm == 'nfs-ls' :
        # daytime   daytime 서비스 확인 및 추가정보 수집 BAE-010 DoS 공격에 취약한 서비스 비활성화
            NessusPluginID = '11356'
            found_flag = True


    # 바로 취약여부를 알 수 없지만, 서비스 사용여부에 도움이 될만한 정보추가
    if found_flag == False :
        if portN == '69' and state == 'open':
			# BAC-013	tftp, talk 서비스 비활성화 
            NessusPluginID = '11819'

        if portN == '161' and state == 'open' and serviceNm == 'snmp':
            # BAA-001 SNMP 서비스 Get community 스트링 설정 오류
            NessusPluginID = '41028'

        if portN == '21' and state == 'open' and serviceNm =='ftp':
            # BAE-011   FTP 서비스 구동 점검
            NessusPluginID = '10092'

        if portN == '25' and state == 'open' and serviceNm =='smtp':
            # BAB-001 SMTP 서비스 실행
            NessusPluginID = '10263'

        if portN == '513' and state == 'open' and serviceNm == 'login':
            # BAE-008   r 계열 서비스 비활성화
            NessusPluginID = '10205'

        if portN == '2049' and state == 'open' and serviceNm == 'nfs':
            # BAC-007   NFS 서비스 비활성화
            NessusPluginID = '11356'

        if portN == '2301' and state == 'open' :
            # BBA-010   HP(Compaq) 웹기반 관리(WBEM) 서비스 실행
            NessusPluginID = '23711'

        if (portN == '7' or portN =='9' or portN == '13' or portN == '19') and state == 'open':
            # BAE-010   DoS 공격에 취약한 서비스 비활성화
            NessusPluginID = '10457'

    return NessusPluginID

def NmapXmlParser(filenames, options):
    oOuput = cOutputCSV(options)
    oOuput.Row(['Plugin ID','Host','Port','Protocol','State','Name', 'Script', 'Synopsis'])
    for filename in filenames:
        domNmap = xml.dom.minidom.parse(open(filename, 'r'))

        nmap_header = domNmap.getElementsByTagName('nmaprun')
        nmap_footer = domNmap.getElementsByTagName('runstats')
        
        for hosttag in domNmap.getElementsByTagName('host'):
            for port in hosttag.getElementsByTagName('port'):
                scriptFound = False
                productStr = ''
                extraStr = ''

                addresses = [address.getAttribute('addr') for address in hosttag.getElementsByTagName('address') if address.getAttribute('addrtype') == 'ipv4']
                row = ['|'.join(addresses)]
                row.append(port.getAttribute('portid'))
                row.append(port.getAttribute('protocol'))
                for state in port.getElementsByTagName('state'):
                    row.append(state.getAttribute('state'))
                for service in port.getElementsByTagName('service'):
                    nameStr = ''
                    nameStr = service.getAttribute('name')
                    if service.getAttribute('product'):
                        productStr = service.getAttribute('product')
                    if service.getAttribute('extrainfo'):
                        extraStr = service.getAttribute('extrainfo')
                    row.append(nameStr)
                if port.getElementsByTagName('script'):
                    scriptFound = True
                    for script in port.getElementsByTagName('script'):
                        row.append(script.getAttribute('id'))
                        row.append(repr(script.getAttribute('output').encode('ascii').replace('\n  ','')))
                        row.insert(0, getNessusPluginID(row))
                        oOuput.Row(row)
                        row.pop(0)
                        row.pop()
                        row.pop()
                row.insert(0, getNessusPluginID(row))
                if row[0] == 'None':
                    row.append('None')
                    row.append('None')
                    row[7] = row[3] + ', Service Name : ' + row[5]
                elif row[0] != 'None' and len(row) == 6:
                    row.append('None')
                    row.append('None')
                    if productStr != '':
                        row[5] = row[5] + ', Product: ' + productStr 
                    if extraStr != '':
                        row[5] = row[5] + ', extraInfo: ' + extraStr
                    row[7] = row[5]
                oOuput.Row(row)
    oOuput.Close()


def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

def Main():
    moredesc = '''
Arguments:
@file: process each file listed in the text file specified
wildcards are supported'''

    oParser = optparse.OptionParser(usage='usage: %prog [options] [@]file ...\n' + __description__ + moredesc, version='%prog ' + __version__)
    oParser.add_option('-o', '--output', type=str, default='', help='Output to file')
    oParser.add_option('-s', '--separator', default=',', help='Separator character (default ;)')
    (options, args) = oParser.parse_args()

    if len(args) == 0:
        oParser.print_help()
    else:
        NmapXmlParser(ExpandFilenameArguments(args), options)

if __name__ == '__main__':
    Main()
