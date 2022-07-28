
import numpy as np
import constants as const
import msgs as msgs
import copy

# State: 
# [FILELOCATION, FILETYPE, N_LINKS, EXPLORED, INSPECT, VULNERABILITY]

class Agent():
    
    def __init__(self,verbose=True):       
        self.Q = {}               
        self.nactions = const.N_ACTIONS
        self.nstates = const.N_STATES    
        self.verbose = verbose
        
    def copy(self):
        newagent = Agent()
        newagent.Q = copy.deepcopy(self.Q)
        newagent.nactions = self.nactions
        newagent.nstates = self.nstates
        newagent.verbose = self.verbose
        
        newagent.eps = self.eps
        newagent.alpha = self.alpha
        newagent.gamma = self.gamma
        return newagent
        
           
    def set_learning_options(self,exploration=0.2,learningrate=0.1,discount=0.9):
        self.eps = exploration
        self.alpha = learningrate
        self.gamma = discount      
    
    def reset(self,env):
        self.env = env  
        self.terminated = False
    
        self.state = np.zeros(self.nstates,dtype='int')
        if not(self.state.tobytes() in self.Q.keys()):
            self.Q[self.state.tobytes()] = np.random.gamma(2,2,self.nactions)
        
        self.focusfile = None
        self.filesystem = None
        
        self.steps = 0
        self.rewards = 0
                
    def run_episode(self,max_iter=np.inf):
        _,_,self.terminated,s = self.env.reset()
        if(self.verbose): print('\nHACKER: Resetting...')
        if(self.verbose): print(s)
        
        while not(self.terminated):
            self.step()
            if self.steps >= max_iter:
                self.terminated = True
            
    def step(self):
        self.steps = self.steps+1
        action = self._select_action()
        
        msg = self._package_action_into_msg(action)
        response,reward,termination,s = self.env.step(msg)
        self.rewards = self.rewards + reward
        
        self._analyze_response(action,msg,response,reward)
        self.terminated = termination
        if(self.verbose): print(s)
        
        return
    
    def _package_action_into_msg(self,action):
        if(action==const.ACTION_SCAN):
            if(self.verbose): print('HACKER: Scanning for visible files...')
            return msgs.ScanMsg()
        
        if(action==const.ACTION_EXPLORE):
            if(self.verbose): print('HACKER: Checking for links in file {0}...'.format(self.focusfile))
            return msgs.ExploreMsg(self.focusfile)
        
        if(action==const.ACTION_INSPECT):
            if(self.verbose): print('HACKER: Checking for vulnerabilities in file {0}...'.format(self.focusfile))
            return msgs.InspectMsg(self.focusfile)
        
        if(const.ACTION_SEND_PARAM1 <=action<= const.ACTION_SEND_PARAM4):
            if(self.verbose): print('HACKER: Sending param {0} to file {1}...'.format(action-2,self.focusfile))
            return msgs.SendMsg(self.focusfile,action-2)
        
        if(action==const.ACTION_FOCUS_NEXT):
            if(self.verbose): print('HACKER: Shifting focus from target file {0} forward...'.format(self.focusfile))
            return msgs.FocusNextMsg(self.focusfile)
        
        if(action==const.ACTION_FOCUS_PREV):
            if(self.verbose): print('HACKER: Shifting focus from target file {0} backward...'.format(self.focusfile))
            return msgs.FocusPrevMsg(self.focusfile) 

       
    def _select_action(self):
        if (np.random.random() < self.eps):
            return np.random.randint(0,self.nactions)        
        else:
            if(self.state.tobytes() in self.Q.keys()):
                return np.argmax(self.Q[self.state.tobytes()])
            else:
                self.Q[self.state.tobytes()] = np.random.gamma(2,2,self.nactions)
                return np.argmax(self.Q[self.state.tobytes()])
            
    def _analyze_response(self,action,attack_msg,response_msg,reward):
        
        response_command = response_msg.command
        attack_command = attack_msg.command
 
        newstate = self.state.copy()
        
        if(response_command==const.SMSG_NONE):
            if(attack_command==const.AMSG_INSPECT):
                newstate[const.STATE_VULNPARAM1:const.STATE_VULNPARAM4] = const.VULN_CLOSED
            
            elif(attack_command==const.AMSG_SEND):
                param = attack_msg.content[1]
                newstate[const.STATE_VULNPARAM1 + param -1] = const.VULN_CLOSED 
                
        elif(response_command==const.SMSG_INVALID):
            pass
            
        elif(response_command==const.SMSG_FILELIST):
            if(self.filesystem==None):
                self.filesystem = response_msg.content
                for v in self.filesystem.nodes():
                    localstate = np.zeros(self.nstates,dtype='int')
                    localstate[const.STATE_FILEVISIBILITY] = const.VISIB_PUBLIC
                    localstate[const.STATE_NLINKS] = self.filesystem.degree[v]
                    self.filesystem.nodes[v]['state'] = localstate
                self.focusfile = 0
                newstate = self.filesystem.nodes[0]['state']
            else:
                pass
        
        elif(response_command==const.SMSG_FILEEDGES):
            nodelist = response_msg.content
            for n in nodelist:
                if not(n in self.filesystem.nodes):
                    self.filesystem.add_edge(self.focusfile,n)
                    localstate = np.zeros(self.nstates,dtype='int')
                    localstate[const.STATE_FILEVISIBILITY] = const.VISIB_HIDDEN
                    localstate[const.STATE_NLINKS] = self.filesystem.degree[n]
                    self.filesystem.nodes[n]['state'] = localstate
            newstate[const.STATE_EXPLORED] = True
                    
        elif(response_command==const.SMSG_VULNLIST):
            vuln = response_msg.content
            newstate[const.STATE_VULNPARAM1:const.STATE_VULNPARAM4] = const.VULN_CLOSED
            newstate[const.STATE_VULNPARAM1 + vuln - 1] = const.VULN_OPEN
            
        elif(response_command==const.SMSG_FLAG):
            pass
        
        elif(response_command==const.SMSG_FILEFOCUS):
            
            self.filesystem.nodes[self.focusfile]['state'] = self.state
            fileindex = np.where(np.array(self.filesystem.nodes) == self.focusfile)[0][0]
            
            if(attack_command==const.AMSG_FOCUSNEXT):               
                if(fileindex == len(self.filesystem.nodes)-1):
                    fileindex = 0
                else:
                    fileindex = fileindex+1
                
            elif(attack_command==const.AMSG_FOCUSPREV):
                if(fileindex == 0):
                    fileindex = len(self.filesystem.nodes)-1
                else:
                    fileindex = fileindex-1
                    
            self.focusfile = list(self.filesystem.nodes)[fileindex]
            newstate = self.filesystem.nodes[self.focusfile]['state']
                               
        self._update_Q(self.state,newstate,action,reward)
        self.state = newstate
            
    def _update_Q(self,oldstate,newstate,action,reward):
        
        if(newstate.tobytes() in self.Q.keys()):
            best_action_newstate = np.argmax(self.Q[newstate.tobytes()])
        else:
            self.Q[newstate.tobytes()] = np.random.gamma(2,2,self.nactions)
            best_action_newstate = np.argmax(self.Q[newstate.tobytes()])
        
        self.Q[oldstate.tobytes()][action] = self.Q[oldstate.tobytes()][action] + self.alpha * (reward + self.gamma*self.Q[newstate.tobytes()][best_action_newstate] - self.Q[oldstate.tobytes()][action])
        
        
        
        
        