from os import name
import paramiko
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.hlapi.asyncore import transport
def hostTableSsh(ipAddres,mainport,):

    stdout=connectSsh(ipAddres,"interface bridge host print ")
    answer=[]
    for line in stdout:
        if(mainport in line):
            continue
        else:
            answer.append(line.strip("\r\n"))
    return answer

def arpTableSsh(ipAddres):
    stdout=connectSsh(ipAddres,"ip arp print")
    answer=[]
    for line in stdout:
        answer.append(line.strip("\r\n"))   
    return answer

def connectSsh(ipAddres,command="system identity print"):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    client.connect(ipAddres,username="admin",password="vtufgfccdjhl",port=7772)
    stdin,stdout,stderr =client.exec_command(command)
    return(stdout)
def matching(addresRouter,addresSwitch,mainPortSwitch):
    file = makeFile(addresSwitch,"-arp-mac-mi")
    arpTable=arpTableSsh(addresRouter)
    hostTable=hostTableSsh(addresSwitch,mainPortSwitch)
    macStartSw=str(hostTable[1]).find("MAC-ADDRES")
    interfaceStart=str(hostTable[1]).find("ON-INTERFACE")
    addresStart=str(arpTable[2]).find("ADDRESS")
    macStartRt=str(arpTable[2]).find("MAC-ADDRES")
    
    for line in arpTable:
        for j in range(2,len(hostTable)-1):
            if(hostTable[j][macStartSw:macStartSw+18].strip().replace(":","-").upper()==line[macStartRt:macStartRt+18].replace(":","-").strip()):
                file.write(hostTable[j][interfaceStart:interfaceStart+17].strip()+" "+line[int(addresStart):int(addresStart)+16].strip()+" "+line[22:40].replace(":","-").strip().upper()+"\n")
    file.close()

def makeFile(ipAddres,parram="",):
    name=connectSsh(ipAddres)
    fileName=""
    for line in name:
        fileName+=line[8:].strip()
    file=open(fileName+parram+".txt","w")
    return file

def makeMacTable(ipAddres,mainPort):
    file=makeFile(ipAddres)
    hostTable=hostTableSsh(ipAddres,mainPort)
    macStart=str(hostTable[1]).find("MAC-ADDRES")
    interfaceStart=str(hostTable[1]).find("ON-INTERFACE")
    for i in range(2,len(hostTable)-1):   
        file.write(hostTable[i][macStart:macStart+18].strip().replace(":","-").upper()+" "+hostTable[i][interfaceStart:interfaceStart+17].strip()+"\n")
    file.close()

def matchingArpMacTable(ipAddres,mainPort,arpFileName):
    file=makeFile(ipAddres,"-arp-mac")
    hostTable=hostTableSsh(ipAddres,mainPort)
    macStart=str(hostTable[1]).find("MAC-ADDRES")
    interfaceStart=str(hostTable[1]).find("ON-INTERFACE")
    arpTable=open(arpFileName+".txt","r")
    for line in arpTable:
        for i in range(2,len(hostTable)-1):
            if(hostTable[i][macStart:macStart+18].strip().replace(":","-").upper()==line[22:40].upper().strip()):
                file.write(line[0:15].strip()+" "+hostTable[i][interfaceStart:interfaceStart+17].strip()+" "+line[22:40].strip().upper()+"\n")

def hostTableDl(ip,community):
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

def matchingDl(ipAddresRouter,ipAddresSwitch,mainPortSwitch,nameSwitch,amountSwitchPort,community="public"):
    file = open(nameSwitch+"-arp-mac.txt","w")
    arptable=arpTableSsh(ipAddresRouter)
    mactable=hostTableDl(ipAddresSwitch,community)
    addresStartRt=str(arptable[2]).find("ADDRES")
    macStartRt=str(arptable[2]).find("MAC-ADDRES")
    tableInfo=[]
    for lineMac in mactable:
        for lineArp in arptable:
            if(str(lineMac)[221:223].replace("]","")!=mainPortSwitch):
                if((str(lineMac)[9:26].replace(":","-").strip().upper())==lineArp[macStartRt:macStartRt+18].replace(":","-").strip()):
                  file.write("port:"+str(lineMac)[221:223].replace("]","").strip()+" "+lineArp[addresStartRt:addresStartRt+15].strip()+" "
                    +str(lineMac)[9:26].replace(":","-").strip().upper()+"\n")
    file.close()

matching("192.168.102.200","192.168.102.148","ether1")      
