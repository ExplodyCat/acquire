import inspect
import psutil
import os
import hashlib
import subprocess
import shutil
import datetime
from shadowcopy import shadow_copy as scopy

args=None
hostName=""
reportLog=["datetime,message,detail"]
acquireList=[]

def debug(msg=""):
    f=inspect.currentframe().f_back
    thisFileName=f.f_code.co_filename
    thisLineNo=f.f_lineno
    print("%s - %d| %s" % (thisFileName, thisLineNo, msg))
    None

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()
    None

def handleExcept(e,postmessage=""):
    appendLogTime("INFO-WARN: %s %s"%(str(e),postmessage))
    print("\x1b[6;30;42m" + str(e)+"\n^^^^^^^^^^^^^^^^^^"+ "\x1b[0m")
    None

def appendLogTime(message="",detail=""):
    global reportLog
    reportLog.append(str(datetime.datetime.now())+","+message+","+detail)
    None

def writeReport(outpath=os.getcwd()+"\\acqResults"):
    if not os.path.exists(outpath):
        os.makedirs(outpath)
    
    with open(outpath+"\\acqLog.csv","w",newline="") as outfile:
        for cur in reportLog:
            outfile.writelines(cur+"\r\n")
    None

def getFile(src,dstDir):
    try:
        dst= dstDir+"\\"+src[src.rfind("\\")+1:]
        
        if os.path.exists(src):
            if (not os.path.exists(dstDir)):
                os.makedirs(dstDir)
            shutil.copy2(src,dstDir)
            if os.path.exists(dst):
                appendLogTime(message="Acquisition: %s"%(src),detail=md5(dst))
        else:
            appendLogTime(message="ACQ Skipped(File DNE): %s"%src)
    except PermissionError:
        try:
            scopy(src,dstDir)
            if os.path.exists(dst):
                appendLogTime(message="Acquisition- UTILIZING SHADOW COPY: %s"%(src),detail=md5(dst))
        except Exception as e:
                handleExcept(e, "SKIPPING ACQ %s"%(src))
    except Exception as e:
            handleExcept(e)
    None

def acquire(dstDir=os.getcwd()+"\\acqResults"):
    if not os.path.exists(dstDir):
        os.makedirs(dstDir)
    getFile("C:\Windows\INF\setupapi.dev.log",dstDir) #Acquire high value log containing usb device connection artifacts
    getFile("C:\Windows\System32\winevt\Logs\Security.evtx",dstDir+"\\winevt")
    getFile("C:\Windows\System32\winevt\Logs\System.evtx",dstDir+"\\winevt")

    regOutDir=dstDir+"\\registry"
    reghives=["C:\Windows\System32\config\SAM","C:\Windows\System32\config\SECURITY","C:\Windows\System32\config\SOFTWARE","C:\Windows\System32\config\SYSTEM"]
    for cur in reghives:
        getFile(cur,regOutDir) #Acquire critical windows registry hives

    for curUser in os.listdir("C:\\Users"):
        tPath="C:\\Users\\"+curUser
        if(os.path.isdir(tPath)):
            src=tPath+"\\NTUSER.DAT"
            if(os.path.exists(src)):
                getFile(src, f"{regOutDir}\\{curUser}")
            src=tPath+"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat" #Acquire registry hive specific to Shellbags
            if(os.path.exists(src)):
                getFile(src, f"{regOutDir}\\{curUser}")

            #Acquire current user's jumplist files
            jmplistOutDir=dstDir+"\\jumplists\\"+curUser      
            jmplistDir=tPath+"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations"
            if(os.path.exists(jmplistDir)):
                for curFile in os.listdir(jmplistDir):
                    getFile(f"{jmplistDir}\\{curFile}",jmplistOutDir+"\\AutomaticDestinations")
            jmplistDir=tPath+"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations"
            if(os.path.exists(jmplistDir)):
                for curFile in os.listdir(jmplistDir):
                    getFile(f"{jmplistDir}\\{curFile}",jmplistOutDir+"\\CustomDestinations")
            

    for cur in acquireList:
        try:
            getFile(cur,dstDir)
        except Exception as e:
            handleExcept(e)
    None

def hostdetails(outpath=os.getcwd()+"\\acqResults"):
    if not os.path.exists(outpath):
        os.makedirs(outpath)
    
    with open(outpath+f"\\{hostName}-netstat.txt","w") as outf:
        outf.writelines("netstat -abno")
        subprocess.Popen("netstat -abno",stdout=outf)

    with open(outpath+f"\\{hostName}-ipconfig.txt","w") as outf:
        outf.writelines("ipconfig")
        subprocess.Popen("ipconfig",stdout=outf)

    outp = outpath+f"\\{hostName}-process"
    os.system(f"wmic process list /format:csv > {outp}.csv")
    os.system(f"wmic process list /format:value > {outp}.txt")

    outp = outpath+f"\\{hostName}-schtasks.csv"
    os.system(f"schtasks /Query /FO CSV /V > {outp}")
    
    for p in psutil.disk_partitions():
        label = p.mountpoint.strip(":\\\\")
        outp = outpath+f"\\{hostName}-directorylist_{label}.txt"
        os.system(f"dir {p.mountpoint} /A /OD /S > {outp}")
    None
    
def main():
    global hostName
    print(f"Acquisition begun @{str(datetime.datetime.now())}")
    hostName=subprocess.check_output("hostname").decode("utf-8").strip("\r\n")
    appendLogTime(f"Acquisition of device {hostName}",hostName)
    hostdetails()
    acquire()
    writeReport()
    print(f"Acquisition completed @{str(datetime.datetime.now())}")
    None

if __name__ == "__main__":
    main()
None
