# Secure Messaging Solution

## License

MIT License

Copyright (c) 2021 Zachary Hannam

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Abstract

Online inter-network communication is an essential part of modern society. It is how you stream music and movies or transact using debit and credit cards. As a population, we often take for granted how easy applications have made this. However, in the haste and drive for profit when creating these services, the security and privacy are often lacking. The purpose of this project is to implement highly secure and privacy driven system for sending encrypted data to other people, such as messages and files. To achieve the level of privacy and security. I took advantage of common, highly tested and, proven secure encryption methods such as RSA, XOR and hashing. As well as tor network integration and commonly accepted practices of data intercommunication. By combining these elements, the system aims to mitigate potential vulnerabilities and safeguard user privacy in online communication. In summary, this project in decentralized secure messaging, aims to contribute to the advancement of online communication by implementing a comprehensive solution that priorities privacy and encryption, and adhere to established security protocols.


## User Manual

User Manual

##
Installing Requirements:

The requirements file is contained in the main directory of the program. It contains all the libraries that are necessary for the program to function fully.

The following command installs packages in bulk according to the configuration file, requirements.txt. In some environments use pip3 instead of pip

> $ pip install -r requirements.txt

## Terminal:

After installing the requirements.txt file, starting a terminal is as simple as opening the Terminal.py file. It is important to remember that creating a publicly available terminal requires port forwarding either the http port (80) or the https port (443).



## Messenger:

After installing the requirements.txt file open the Messenger.py file. The user will then be shown a list of all commands as well as an input line at the bottom of the terminal screen.

To input a command, type ‘/’ followed by the chosen command (Replace the ‘/’ with the command key listed in the properties file if you have changed it). If an exception occurs, during the processing or performing of your command, you will be sent a well-informed exception message.

##

Usages are formatted as follows:

The command: /…

Positional Arguments: <…>

Key word arguments [-…]

To enter a command, write the full command, following by all positional arguments split by spaces. If you wish to use a key word argument, write “- “, followed by the name of the key word argument followed by a space and then the value you wish to set the argument to.

## Messenger Commands:

> create_server:

Used when a user wishes to create a server that is publicly available for people to join.

Usage: /create_server <terminal> [-channel_id] [-secret_key] [-port] [-public] [-join] [-name]

terminal (str) -> The URL of the terminal, including http or https and a designated port if using a non-default http or https port.

channel_id (str) -> The chosen channel id / server name

secret_key (str) -> The chosen secret key

port (int) -> The chosen port to host the server on. By default, this is 28961

public (bool) -> If the channel id / server name should be shown in plaintext on the terminal. By default, this is false.

join (bool) -> If the user should automatically join the server. By default, this is true.

name (str) -> If the user wishes to join the created server, this key word argument allows them to choose their display name.

Reminder: If you wish to start a server, you must port forward the chosen port in which you want to host it.

> delete_server:

Used when a user wishes to delete their server.

Usage: /delete_server [-channel_id]

channel_id (str) -> The chosen channel id / server name. By default, this is the active server.

> join_server:

Used when a user wishes to join publicly listed server on a terminal.

Usage: /join_server <terminal> <channel_id> [-name] [-server secret] [-tor_port]

terminal (str)-> The URL of the terminal, including http or https and a designated port if using a non-default http or https port.

channel_id (str) -> The channel id / server name of the server you wish to join.

name (str) -> The chosen display name the user wishes to join the server.

server_secret (str) -> If you have the server secret, you can join the server using that to gain elevated privileges.

tor_port (int) -> If you wish to use the tor network as a proxy, you can enter the port of the tor application running on your computer. By default, this is none.

> leave_server:

Used when you wish to leave a server.

Usage: /leave_server [-channel_id]

channel_id (str) -> The channel id / server name of the server you wish to leave. If none is provided, then it will leave the active server.

> active_server and active_client:

Used to set the active server or client. When sending a message or performing some commands, it will automatically use the active server / client.

Usage: /active_server <channel_id>

Usage: /active_client <channel_id>

channel_id (str) -> The channel id / server name of the server you wish to set as active. If none is provided, then it will leave the active server.

> send_file:

The command used to send a file or directory to other users on the server.

Usage: /send_file <file_path> [-channel_id]

file_path (str) -> The path of the file or directory you wish to send to other users on the server.

channel_id (str) -> The channel id / server name of the server you wish to send a file to. If none is provided, then it will send the file to the active server.

> exit:

Used to exit the messenger application. Will automatically stop all hosted servers and leave other servers.

Usage: /exit
