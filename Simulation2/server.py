
import constants as const

import numpy as np

class Msg():
    def __init__(self,command,content):
        self.command = command
        self.content = content


class Server():
    
    def __init__(self,nport,vulnport,probdetection=0.0):
        self.nport = nport
        self.vulnport = vulnport
        self.probdetection = probdetection
        self.termination = False
        
    def step(self,action):
        command = action.command
        
        if (command == const.SCAN):
            msg = Msg(const.OPENPORT, self.vulnport)
            
            if(np.random.random()<self.probdetection):
                self.vulnport = np.random.randint(1,self.nport+1)
            
            return msg,0,self.termination,'Discovered open port(s)'
        
        elif(command == const.ATTACK):
            target = action.content
            if(target==self.vulnport):
                self.termination = True
                msg = Msg(const.FLAG, None)
                return msg,100,self.termination,'Flag captured'
            else:
                msg = Msg(const.NONE, None)
                return msg,-1,self.termination,'Nothing happened'
    
    def reset(self):
        self.termination = False
        return None,0,self.termination,'\nGame reset'
        
        
   
        