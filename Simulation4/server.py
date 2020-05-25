
import constants as const
import msgs as msgs

class Server():
    
    def __init__(self, visiblefilesystem, filesystem, vulnfile, vulnparam):      
        self.visiblefilesystem = visiblefilesystem
        self.filesystem = filesystem
        self.vulnfile = vulnfile
        self.vulnparam = vulnparam
        
        self.termination = False
        
    def step(self,action):
        command = action.command
        
        if (command == const.AMSG_SCAN):
            msg = msgs.FileListMsg(self.visiblefilesystem.copy())
            return msg,-1,self.termination,'SERVER: Sending list of visible files: {0}'.format([const.STRING_VISIBLEFILES[f] for f in list(self.visiblefilesystem.nodes())])
        
        elif (command == const.AMSG_EXPLORE):
            targetfile = action.content
            if(targetfile == None):
                msg = msgs.InvalidCmdMsg()
                return msg,-1,self.termination,'SERVER: Wrong command content'
            else:
                adjfiles = list(self.filesystem.adj[targetfile])
                msg = msgs.FileEdgesMsg(adjfiles)
                return msg,-1,self.termination,'SERVER: Sending list of files connected to {0}'.format(const.STRING_ALLFILES[targetfile])
        
        elif (command == const.AMSG_INSPECT):
            targetfile = action.content
            if(targetfile == None):
                msg = msgs.InvalidCmdMsg()
                return msg,-1,self.termination,'SERVER: Wrong command content'
            elif (self.vulnfile == targetfile):
                msg = msgs.VulnParamMsg(self.vulnparam)
                return msg,-1,self.termination,'SERVER: Discovered exploitable vulnerability in file {0} with param: {1}'.format(const.STRING_ALLFILES[targetfile], self.vulnparam)
            else:
                msg = msgs.NoneMsg()
                return msg,-1,self.termination,'SERVER: No exploitable vulnerability present'
            
        elif (command == const.AMSG_SEND):
            targetfile = action.content[0]
            targetparam = action.content[1]
            
            if(targetfile == None):
                msg = msgs.InvalidCmdMsg()
                return msg,-1,self.termination,'SERVER: Wrong command content'
            if(targetfile==self.vulnfile and targetparam==self.vulnparam):
                self.termination = True
                msg = msgs.FlagMsg()
                return msg,100,self.termination,'SERVER: Flag captured'
            else:
                msg = msgs.NoneMsg()
                return msg,-1,self.termination,'SERVER: Access Attempt Failed'
            
        elif (command==const.AMSG_FOCUSNEXT or command==const.AMSG_FOCUSPREV):
            targetfile = action.content
            if(targetfile == None):
                msg = msgs.InvalidCmdMsg()
                return msg,-1,self.termination,'SERVER: Wrong command content'
            else:
                msg = msgs.FileFocusMsg()
                return msg,-1,self.termination,'SERVER: File focus shift'
    
    def reset(self):
        self.termination = False
        return None,0,self.termination,'SERVER: Server reset'
        