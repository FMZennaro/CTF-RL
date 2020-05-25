# Simulation 4

In this scenario we run a reinforcement learning exercise resembling a web hacking scenario.

The learning environment is given by a target **Server**. The server hosts *nvisible* visible files that are advertised on the network and *nhidden* hidden files that are not publicly available on the network but are linked to visible files. One of the files has a parametrized vulnerability, and behind it lies a flag. Only one file is vulnerable.

The attacker is an **Agent** that can interact with the server through different types of commands:
- *Scan*: this command retrieves the graph of visible files
- *Explore*: this command is targeted to a specific file, and it allows the attacker to discover hidden files connected to it.
- *Inspect*: this command is targeted to a specific file, and it allows the attacker to detect a parametrized vulnerability (if present).
- *Send*: this command is targeted to a specific file, and it allows the attacker to send a vulnerable parameter.

The attacker also has a mock command that does not imply any exchange of messages with the target server.
- *Focus Next* and *Focus Prev*: this command allows the agent to shift its focus among the files on the server.

At every episode the Server is reinitialized with a single flag in a random place.

Server and attackers interact exchanging **Msgs**.

The aim of the attacker is to develop an optimal strategy to win the game in the least number of steps.

The attacker starts with no knowledge about the configuration of the server or the semantic of the messages it can send. Learning happens with a tabular Q-learning instantiated at run-time relying on state aggregation.