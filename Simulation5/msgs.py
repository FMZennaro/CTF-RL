
import constants as const

class Msg():
    def __init__(self,command,content):
        self.command = command
        self.content = content
        
class ScanMsg(Msg):
    def __init__(self):
        super().__init__(const.AMSG_SCAN, None)
        
class ReadMsg(Msg):
    def __init__(self,port):
        super().__init__(const.AMSG_READ, port)
        
class DeepReadMsg(Msg):
    def __init__(self,port):
        super().__init__(const.AMSG_DEEPREAD, port)
        
class AccessMsg(Msg):
    def __init__(self,port,accesspoint):
        super().__init__(const.AMSG_ACCESS, [port,accesspoint])
        
class SendMsg(Msg):
    def __init__(self,port,param):
        super().__init__(const.AMSG_SEND, [port,param])
        

class NoneMsg(Msg):
    def __init__(self):
        super().__init__(const.SMSG_NONE, None)

class OpenPortMsg(Msg):
    def __init__(self,port):
        super().__init__(const.SMSG_OPENPORT, port)
        
class AccessPointsMsg(Msg):
    def __init__(self,accesspoints):
        super().__init__(const.SMSG_AVAILABLE_ACCESSPOINTS, accesspoints)
        
class VulnParamMsg(Msg):
    def __init__(self,vulnparam):
        super().__init__(const.SMSG_VULNPARAM, vulnparam)
        
class FlagMsg(Msg):
    def __init__(self):
        super().__init__(const.SMSG_FLAG, None)