from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.hlapi.asyncore import transport
def fetch_fdb(ip,community):
    mib='1.3.6.1.2.1.17.7.1.2.2.1.2'
    value= tuple([int(i) for i in mib.split('.')])
    generator=cmdgen.CommandGenerator()
    comm_data=cmdgen.CommunityData('server',community,1)
    transport = cmdgen.UdpTransportTarget((ip,161))
    real_fun=getattr(generator,"nextCmd")
    (errorIndication, errorStatus, errorIndex, varBindTable) = real_fun(comm_data, transport, value)
    if errorIndication is not None or errorStatus is True:
        print('IP: %s Error: %s %s %s %s' % (ip, errorIndication, errorStatus, errorIndex, varBindTable))
    else:
        for varBindTableRow in varBindTable:
            data = varBindTableRow[0][0][len(value):]
            vlan = data[0]
            mac = '%02X:%02X:%02X:%02X:%02X:%02X' % tuple(map(int, data[-6:]))
            port = varBindTableRow[0][1]
            yield {'mac': mac, 'port': port}
def hostTable(namefile,mainPort,ipAddres):
    answer=open(namefile+".txt","w")
    fdb = fetch_fdb(ipAddres, 'public')
    for fdb_rec in fdb:
        test=str(fdb_rec)
        if(test[221:223].replace("]","")==mainPort):
            continue
        else:
            answer.write(test[9:26].replace(":","-").upper()+"  "+test[221:223].replace("]","")+"\n")
    answer.close()
hostTable("sw-4z-vid4","25","192.168.100.99")

