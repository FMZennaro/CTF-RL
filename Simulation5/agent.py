
import numpy as np
import constants as const
import msgs as msgs 



class Agent():
    
    def __init__(self,verbose=True):       
        self.Q = {}               
        self.nactions = const.N_ACTIONS        
        self.verbose = verbose
        
        
    def set_learning_options(self,exploration=0.2,learningrate=0.1,discount=0.9):
        self.eps = exploration
        self.alpha = learningrate
        self.gamma = discount      
    
    def reset(self,env):
        self.env = env  
        self.terminated = False
        
        self.state = np.zeros((const.N_PORTS, 1+const.N_ACCESSPOINTS+1),dtype='int')
        if not(self.state.tobytes() in self.Q.keys()):
            self.Q[self.state.tobytes()] = np.random.gamma(2,2,self.nactions)
        
        self.steps = 0
        self.rewards = 0
                
    def run_episode(self):
        _,_,self.terminated,s = self.env.reset()
        if(self.verbose): print('\nHACKER: Resetting...')
        if(self.verbose): print(s)
        
        while not(self.terminated):
            self.step()
            #if(self.steps>500): self.terminated=True
                      
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
    
    def run_trajectory(self,trajectory):
        _,_,self.terminated,s = self.env.reset()
        if(self.verbose): print('\nHACKER: Resetting...')
        if(self.verbose): print(s)
        
        for t in range(len(trajectory)):
            self.steps = self.steps+1
            action = trajectory[t]
            
            msg = self._package_action_into_msg(action)
            response,reward,termination,s = self.env.step(msg)
            self.rewards = self.rewards + reward
            
            self._analyze_response(action,msg,response,reward)
            self.terminated = termination
            if(self.verbose): print(s)
        
        return
            
            
        
    
    def _package_action_into_msg(self,action):
        if(action==0):
            if(self.verbose): print('HACKER: Scanning for open ports...')
            return msgs.ScanMsg()
        
        if(1<= action <= const.N_PORTS):
            port = action-1
            if(self.verbose): print('HACKER: Reading port {0}...'.format(const.STRING_PORTS[port]))
            return msgs.ReadMsg(port)
        
        if(const.N_PORTS+1 <= action <= const.N_PORTS*2):
            port = action - const.N_PORTS -1
            if(self.verbose): print('HACKER: Deep reading on port {0}...'.format(const.STRING_PORTS[port]))
            return msgs.DeepReadMsg(port)
        
        if((const.N_PORTS*2)+1 <= action <= const.N_PORTS*(2+const.N_ACCESSPOINTS)):
            port = np.floor_divide((action - 2*const.N_PORTS -1),const.N_ACCESSPOINTS)
            accesspoint = np.remainder((action - 2*const.N_PORTS -1),const.N_ACCESSPOINTS)
            if(self.verbose): print('HACKER: Trying to access service {0} on port {1}...'.format(const.STRING_ACCESSPOINTS[accesspoint],const.STRING_PORTS[port]))
            return msgs.AccessMsg(port, accesspoint)
        
        if(const.N_PORTS*(2+const.N_ACCESSPOINTS)+1 <= action <= const.N_PORTS*(2+const.N_ACCESSPOINTS+const.N_VULNPARAMS)):
            port = np.floor_divide((action - const.N_PORTS*(2+const.N_ACCESSPOINTS) -1),const.N_VULNPARAMS)
            param = np.remainder((action - const.N_PORTS*(2+const.N_ACCESSPOINTS) -1),const.N_VULNPARAMS)+1
            if(self.verbose): print('HACKER: Trying to send param {0} on port {1}...'.format(param,const.STRING_PORTS[port-1]))
            return msgs.SendMsg(port, param)
       
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
 
        if(response_command==const.SMSG_NONE):
            if(attack_command==const.AMSG_READ):
                port = attack_msg.content
                newstate = self.state.copy()
                newstate[port,0] = const.PORT_STATE_CLOSED
                newstate[port,1:-1] = const.ACCESSPOINTSTATE_DOWN
                newstate[port,-1] = const.VULNPARAMS_NONE
            
            elif(attack_command==const.AMSG_DEEPREAD):
                port = attack_msg.content
                newstate = self.state.copy()
                newstate[port,-1] = const.VULNPARAMS_NONE
                
            elif(attack_command==const.AMSG_ACCESS):
                port = attack_msg.content[0]
                accesspoint = attack_msg.content[1]
                newstate = self.state.copy()
                newstate[port,1+accesspoint] = const.ACCESSPOINTSTATE_DOWN
                
            elif(attack_command==const.AMSG_SEND):
                newstate = self.state.copy()
                
        elif(response_command==const.SMSG_OPENPORT):
            port = response_msg.content
            newstate = self.state.copy()
            newstate[:,0] = const.PORT_STATE_CLOSED
            newstate[port,0] = const.PORT_STATE_OPEN
            
        elif(response_command==const.SMSG_AVAILABLE_ACCESSPOINTS):
            port = attack_msg.content
            accesspoints = response_msg.content 
            newstate = self.state.copy()
            for a in accesspoints:
                newstate[port,1+a] = const.ACCESSPOINTSTATE_OPEN
        
        elif(response_command==const.SMSG_VULNPARAM):
            port = attack_msg.content
            param = response_msg.content 
            newstate = self.state.copy()
            newstate[port,-1] = param-1
            
        elif(response_command==const.SMSG_FLAG):
            newstate = self.state.copy()
                
        self._update_Q(self.state,newstate,action,reward)
        self.state = newstate
            
    def _update_Q(self,oldstate,newstate,action,reward):
        
        if(newstate.tobytes() in self.Q.keys()):
            best_action_newstate = np.argmax(self.Q[newstate.tobytes()])
        else:
            #print('A) {0}'.format(newstate))
            self.Q[newstate.tobytes()] = np.random.gamma(2,2,self.nactions)
            best_action_newstate = np.argmax(self.Q[newstate.tobytes()])
        
        self.Q[oldstate.tobytes()][action] = self.Q[oldstate.tobytes()][action] + self.alpha * (reward + self.gamma*self.Q[newstate.tobytes()][best_action_newstate] - self.Q[oldstate.tobytes()][action])
        
        
        
        
        