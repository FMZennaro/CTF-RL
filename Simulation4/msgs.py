
import constants as const

class Msg():
    def __init__(self,command,content):
        self.command = command
        self.content = content
        
class ScanMsg(Msg):
    def __init__(self):
        super().__init__(const.AMSG_SCAN, None)
        
class ExploreMsg(Msg):
    def __init__(self,file):
        super().__init__(const.AMSG_EXPLORE, file)
        
class InspectMsg(Msg):
    def __init__(self,file):
        super().__init__(const.AMSG_INSPECT, file)
        
class SendMsg(Msg):
    def __init__(self,file,param):
        super().__init__(const.AMSG_SEND, [file,param])
        
class FocusNextMsg(Msg):
    def __init__(self,file):
        super().__init__(const.AMSG_FOCUSNEXT, file)
        
class FocusPrevMsg(Msg):
    def __init__(self,file):
        super().__init__(const.AMSG_FOCUSPREV, file)
        

class NoneMsg(Msg):
    def __init__(self):
        super().__init__(const.SMSG_NONE, None)
        
class InvalidCmdMsg(Msg):
    def __init__(self):
        super().__init__(const.SMSG_INVALID, None)

class FileListMsg(Msg):
    def __init__(self,files):
        super().__init__(const.SMSG_FILELIST, files)
        
class FileEdgesMsg(Msg):
    def __init__(self,fileedges):
        super().__init__(const.SMSG_FILEEDGES, fileedges)
        
class VulnParamMsg(Msg):
    def __init__(self,vuln):
        super().__init__(const.SMSG_VULNLIST, vuln)
        
class FlagMsg(Msg):
    def __init__(self):
        super().__init__(const.SMSG_FLAG, None)
        
class FileFocusMsg(Msg):
    def __init__(self):
        super().__init__(const.SMSG_FILEFOCUS, None)