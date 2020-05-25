
import constants as const
import msgs as msgs



# server = new Server(3, const.VULNTYPE_ACCESSPOINT, 
#                     const.VULNLEVEL_NONE,
#                     [const.ACCESSPOINT_ASPNET,const.ACCESSPOINT_DRUPAL])
# 
# server = new Server(4, const.VULNTYPE_PARAM, 
#                     const.VULNLEVEL_DEEP,
#                     const.VULNPARAMS_2)

class Server():
    
    def __init__(self,vulnport,vulnlevel,vulntype,vulnvalue):      
        self.nport = const.N_PORTS
        
        self.vulnport = vulnport
        self.vulntype = vulntype
        self.vulnlevel = vulnlevel
        self.vulnvalue = vulnvalue
        
        self.termination = False
        
    def step(self,action):
        command = action.command
        
        if (command == const.AMSG_SCAN):
            msg = msgs.OpenPortMsg(self.vulnport)
            return msg,-1,self.termination,'SERVER: Discovered open port: {0}'.format(const.STRING_PORTS[self.vulnport])
        
        elif (command == const.AMSG_READ):
            targetport = action.content
            
            if(targetport==self.vulnport and self.vulntype==const.VULNTYPE_ACCESSPOINT):
                msg = msgs.AccessPointsMsg(self.vulnvalue)
                [const.STRING_ACCESSPOINTS[a] for a in self.vulnvalue]
                return msg,-1,self.termination,'SERVER: Discovered accesspoints: {0}'.format([const.STRING_ACCESSPOINTS[a] for a in self.vulnvalue])
            
            elif(targetport==self.vulnport and self.vulntype==const.VULNTYPE_PARAM and self.vulnlevel==const.VULNLEVEL_PLAIN):
                msg = msgs.VulnParamMsg(self.vulnvalue)
                return msg,-1,self.termination,'SERVER: Discovered vulnerable param: {0}'.format(self.vulnvalue)
            
            else:
                msg = msgs.NoneMsg()
                return msg,-1,self.termination,'SERVER: Read Failed'
        
        elif (command == const.AMSG_DEEPREAD):
            targetport = action.content
            
            if(targetport==self.vulnport and self.vulntype==const.VULNTYPE_PARAM and self.vulnlevel==const.VULNLEVEL_DEEP):
                msg = msgs.VulnParamMsg(self.vulnvalue)
                return msg,-1,self.termination,'SERVER: Discovered vulnerable param: {0}'.format(self.vulnvalue)
            
            else:
                msg = msgs.NoneMsg()
                return msg,-1,self.termination,'SERVER: DeepRead Failed'
            
        elif (command == const.AMSG_ACCESS):
            targetport = action.content[0]
            targetservice = action.content[1]
            
            if(targetport==self.vulnport and self.vulntype==const.VULNTYPE_ACCESSPOINT and targetservice in self.vulnvalue):
                self.termination = True
                msg = msgs.FlagMsg()
                return msg,100,self.termination,'SERVER: Flag captured'
            
            else:
                msg = msgs.NoneMsg()
                return msg,-1,self.termination,'SERVER: Access Attempt Failed'
            
        elif (command == const.AMSG_SEND):
            targetport = action.content[0]
            attackparam = action.content[1]
            
            if(targetport==self.vulnport and self.vulntype==const.VULNTYPE_PARAM and attackparam==self.vulnvalue):
                self.termination = True
                msg = msgs.FlagMsg()
                return msg,100,self.termination,'SERVER: Flag captured'
            
            else:
                msg = msgs.NoneMsg()
                return msg,-1,self.termination,'SERVER: Param Exploit Failed'
    
    def reset(self):
        self.termination = False
        return None,0,self.termination,'SERVER: Server reset'
        
        
   
        