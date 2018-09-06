# Teamech

## Introduction
For many folks who work on technology, the "Internet of Things" has become a scary term. It 
brings to mind completely frivolous and frighteningly insecure systems that let you use your
smartphone to control your household appliances remotely, usually involving a propretary app
and company-hosted web service for each device. In spite of how awful this is, I don't think
that the core concept of networked devices is always useless and silly, and for the few 
particular applications where network control makes sense, it's possible to implement it in
a simple, useful, and sane way. Teamech is my first attempt to do this. It attempts to be a
minimal, easy-to-understand SCADA system for controlling small networks of devices on the 
scale of a household or laboratory, with adequate security and very small resource footprint.
The main embedded device I have in mind is the Raspberry Pi, which has enough computing power
to do a lot of neat things while remaining low-power and inexpensive. A Pi can currently act
as either a server or a client on the network; In the future, versions of the client targeting 
smaller and cheaper microcontroller modules are also planned.

## Network Architecture
Teamech uses a star topology for its networks. Networks must include exactly one server, but
may include any number of clients. Messages sent from one client to the server are relayed to
all other clients. The transport layer is UDP, chosen over TCP to allow greater downtime for 
client devices and keep latency as low as possible. By default, Teamech servers listen and 
transmit on UDP port 6666, but this is configurable. Clients may use any free port.
As UDP is a connectionless protocol, Teamech uses "subscriptions" to manage which packets are
sent where. When a new client sends a valid encrypted message to the server, the server adds 
it to a list of "subscribed" (active) clients, and begins relaying messages from other clients 
to the new client. Clients are unsubscribed when they cancel their subscription or fail to 
acknowledge a relayed message.

## Communication
Whenever a client wants to send a message over a Teamech network, it simply timestamps and 
encrypts a message of arbitrary length (between 0 and 476 characters) and sends it to the
server. The server will then reply with a single-byte status code that indicates whether the
packet was relayed or not, and why.
These status codes are as follows:
**0x06 ACK** - The packet was received, validated, and relayed to one or more other clients.
**0x02 START OF TEXT** - The packet was received and validated, and the sender has been added
to the list of subscribed clients. Usually, this is shortly followed by 0x06 or 0x03.
**0x03 END OF TEXT** - The packet was received and validated, but there are no other
subscribed clients on the server to relay it to.
**0x1A SUBSTITUTE** - The packet may or may not have been valid, but the server encountered an
internal error that prevented it from being validated or relayed.
**0x19 END OF MEDIUM** - The packet did not validate; if the client was subscribed, they have
been unsubscribed, and the packet was not relayed.
**0x15 NAK** - The packet was of inappropriate length or type, and was not processed.
When relaying packets, the server expects to get 0x06 as a response. It will try up to three
times to send the packet to each client before giving up. Clients which have been given up on
five times without responding are automatically unsubscribed.
Messages whose content consists of a single byte of value below **0x1F** (non-printing ASCII
control characters) are reserved for client-server messages. Currently, two of these are
implemented:
**0x06 ACK** - Response to being sent a non-control message (from other clients). 
**0x18 CANCEL** - Cancels subscription, informing the server that the client should no longer
be sent messages from other clients.

## Security
Teamech includes its own custom encryption scheme, Teacrypt, which is designed to be simple 
and reasonably secure. While it should not be relied upon in cases where security is critical,
it should be good enough to prevent your nosy neighbors, IT department, or local police from
spying on you thanks to its high toughness against brute-force decryption and man-in-the-
middle attacks. Teacrypt provides integrity verification for all messages and requires clients
to authenticate using their encryption keys before they can subscribe; messages that were not
encrypted correctly with the same key that the server uses are rejected and not relayed.
As a symmetric-key algorithm, however, Teacrypt relies on the physical security of both the 
server and the client devices, and so these devices must be trusted and physically accounted 
for at all times for the network to remain secure. Additionally, exchange of keys must be done 
out-of-band before a client can contact a server.
Note that while Teacrypt can be used for such, Teamech does not offer end-to-end encryption; 
the server can and does log messages sent through it, and will not relay messages that it 
cannot open and log the contents of. It is assumed that a Teamech server will be secure and
run by a trusted party (ideally the same person who owns/manages the client devices).

## Server
The Teamech server is essentially a very simple packet relay with message authentication. It
can run on very low-powered hardware, and requires network throughput capability equal to the
maximum continuous throughput from each client times the typical number of clients. For most 
control applications, this throughput will be very low.
The server can be run from the command line like so:
`./teamech-server [port number] [path to pad file]`
For example, if the port to use is 6666 and the pad file is in the current directory and called
`teamech.pad`, then the command would be
`./teamech-server 6666 teamech.pad`
The server will provide fairly verbose output to stdout every time something happens, which is
useful to be able to glance over if anything goes wrong. An upcoming version of the server will
log all of these messages to a file in addition to the console.

## Client
The only functional client at the moment is the Teamech Desktop console client, which is
intended to serve as the master control interface for the Teamech network's human operator. The
console client uses ncurses to provide a simple scrolling command-line interface somewhat
reminiscent of console-based IRC clients. You can type messages into a simple input line, and 
press enter to have them encrypted and sent to the server. When the server replies with a status
code, the code will appear in hex form on the far right end of the corresponding line.
An embedded (non-user-facing) template version of the client is planned. This will simply be the
desktop client stripped of all user input and ncurses-related code, primarily designed to be run
on a Raspberry Pi controlling a piece of equipment using its GPIO or serial interfaces.

## Mobile Support
No native support for mobile devices is planned - I have no intention of developing an app for 
Android / iOS or any other smartphone-oriented platform. Extremely basic support for Android may
eventually be achieved using a client written in Python and an app providing a terminal 
environment such as Termux, and web-based clients are not out of the question, but smartphones
are not and will not become a focus of this project.
