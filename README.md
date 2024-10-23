# **Network Socket Programming Project**

## Inspired by university assignment ( _University of Iowa - Intro to Networks and Their Applications_ )

### **Author** : Jonathan Boyd

### **Credibility** : Cisco CCNA , CompTIA Network + , CompTIA Security + certified.

#### verify
##### **CCNA** (_b3166ceff8b24529adb2c4de48c0c4c0_)
##### **Network+** (_DWZJP8N6G1EQQBCL_)
##### **Security+** (_RGP8QR5RHFV1QECH_)

### THIS PROJECT REPOSITORY IS ACCOMPANIED WITH DOCUMENTATION.

#### **Credits**<br>

<ul>
    <li>
        <strong>Abhishek CSEPracticals</strong> : <emphasis>provided introduction to socket programming</emphasis>
    </li>
    <li>
        <strong>ArjanCodes</strong> : <emphasis>provided introduction to professional Python programming best practices</emphasis>
    </li>
    <li>
        <strong>Lewis Van Winkle</strong> : <emphasis>provided detailed introduction to socket programming</emphasis>
    </li>
</ul>

This project repository consists of a specific instance of a non-specific assortment of modules. The context of the specific instance is a chat room, as assigned in a university networking course. The function of the chat room instance is associated with the two files ... <code>server.py</code> and <code>client.py</code>.

To properly test the specific instance...

<ol>
    <li>Run the <code>server.py</code> file on an Ubuntu terminal. Enure that all files are in the originally cloned folder. The server.py file can be run at the command line as <code>python server.py</code> or <code>python server.py {service port}</code>. The latter version of command line argument will initiate the server instance on a user-defined ephemeral service port. Otherwise, the server utilizes port 8080. The server will output the ip address being utilized for client connections upon initiation. The location of a failure in server initialization will be readily outputed before program failure.</li>
    <li>Run the <code>client.py</code> file on a given number of Ubuntu terminals, to simulate client connections. If the <code>server.py</code> file is ran with default settings ( i.e., <code>python server.py</code>), then the <code>client.py</code> file can be run with the default <code>python client.py</code> command or a user-specified <code>python client.py {ip address} {service port}</code> command. If the server is initiated with a user-defined command line argument then the client must also be initiated as such.</li>
</ol>

The server will output the process of client connections and disconnections and allows for statistics monitoring. See <code>documentation-database_lib</code> -> <code>Database.audit</code> for details on the results of typing <code>audit</code> in the server terminal.

The server will produce a file which stores user login credentials and a file which serves as a log of server errors and operation. The login functionality is at baseline insignificant, as it only prevents an existing user from loggining in without a previously learned password. Password complexity and new database entry restrictions will have to be implemented by the forker.
<br><br>
<sub>
This project provides an open-source display of a <code>socket programming</code> server-client model. The language is <code>Python</code>. The format/style of coding reflects a developing sense of coding best practices.

The project consists of two network communications modules (<code>net_sec_lib</code> and <code>net_comms_lib</code>). These libraries depend heavily on the <code>socket</code> module. The <code>net_sec_lib</code> module utilizes the <code>cryptography</code> module to incorporate encryption into network socket communications.

The <code>database_lib</code> module is designed to be expandable. Complications with JSON serialization and custom encoders / decoders led to a heavy dependence on dictionaries rather than class composition.
</sub>
