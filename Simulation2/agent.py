
import numpy as np
import server as srv
import constants as const


class Agent():
    
    def __init__(self,nports,verbose=True):       
        self.nports = nports
        self.Q = np.ones((nports+1,nports+1))
        
        self.verbose = verbose
        
    def set_learning_options(self,exploration=0.2,learningrate=0.1,discount=0.9,scanprobability=0.2):
        self.eps = exploration
        self.alpha = learningrate
        self.gamma = discount
        self.beta = scanprobability        
    
    def reset(self,env):
        self.env = env  
        self.terminated = False
        self.steps = 0
        self.state = 0
        
        
    def run_episode(self):
        _,_,self.terminated,s = self.env.reset()
        if(self.verbose): print(s)
        
        while not(self.terminated):
            self.step()
            
    def step(self):
        self.steps = self.steps + 1
        action = self._select_action()
        
        msg = self._package_action_into_msg(action)
        response,reward,termination,s = self.env.step(msg)
        
        self._analyze_response(action,response,reward)
        self.terminated = termination
        if(self.verbose): print(s)
        
        return
    
    def _package_action_into_msg(self,action):
        if(action==0):
            return srv.Msg(const.SCAN,None)
        else:
            return srv.Msg(const.ATTACK,action)
       
    def _select_action(self):
        if (np.random.random() < self.eps):
            if (np.random.random() < self.beta):
                return 0
            else:
                return np.random.randint(1,self.nports+1)        
        else:
            return np.argmax(self.Q[self.state,:])
            
    def _analyze_response(self,action,response,reward):
        command = response.command
        
        if(command==const.NONE):
            self._update_Q(self.state,self.state,action,reward)
            
        elif(command==const.OPENPORT):
            newstate = response.content
            self._update_Q(self.state,newstate,action,reward)
            self.state = newstate
        
        elif(command==const.FLAG):
            self._update_Q(self.state,self.state,action,reward)
            
    def _update_Q(self,oldstate,newstate,action,reward):
        
        best_action_newstate = np.argmax(self.Q[newstate,:])
        self.Q[oldstate,action] = self.Q[oldstate,action] + self.alpha * (reward + self.gamma*self.Q[newstate,best_action_newstate] - self.Q[oldstate,action])
        
        
        
        
        