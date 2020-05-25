# Simulation 1

In this simple scenario the learning environment is given by a target **Server**. The server has *nports* points of attack; only one *vulnport* is open, and behind it lies a flag.

At every episode the vulnerable port changes.

Server and attackers interact exchanging **Msgs**.

The attacker can send two types of command:
- *Scan*: this command does not take any parameter and it returns the vulnport of the server; 
- *Attack*: this command takes as parameter a target port and it returns the outcome of the attack.
In total the attacker has $nports+1$ possible actions.

The attacker starts with no knowledge about the configuration of the server or the semantic of the messages it can send. Learning happens with a tabular Q-learning.