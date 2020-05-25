# Simulation 5

This is an extension of Simulation 3 using imitation learning.

The learning environment is given by a target **Server**. The server has *nports* points of attack. Each *port* may be open or close, it may have a vulnerable listening process running on the port, or it may be vulnerable to a parametrized exploit. 

The attacker is an **Agent** can interact with the server through different types of commands:
- *Scan*: this command detect the presence of an open port.
- *Read*: this command is targeted to a specific port, and it allows the attacker to detect the presence of a vulnerable process or the presence of a parametrized vulnerability (if in plain sight).
- *DeepRead*: this command is targeted to a specific port, and it allows the attacker to detect a parametrized vulnerability (if hidden).
- *Access*: this command is targeted to a specific port, and it allows the attacker to take over a listening process.
- *Send*: this command is targeted to a specific door, and it allows the attacker to execute and exploit by sending a vulnerable parameter.

At every episode the Server is reinitialized with a single flag in a random place.

Server and attacker interact exchanging **Msgs**.

The aim of the attacker is to develop an optimal strategy to win the game in the least number of steps.

The attacker starts with no knowledge about the configuration of the server or the semantic of the messages it can send. Learning happens with a tabular Q-learning instantiated at run-time in a lazy fashion.