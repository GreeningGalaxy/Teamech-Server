# Teamech
## A Simple Application Layer for the Intranet of Things
  
### Introduction
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
  
### Network Architecture
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
  
### Communication
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
  
### Security
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
  
### Server
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
  
### Clients
There are two clients available for Teamech: the [desktop client](https://github.com/diodelass/Teamech-Desktop "Teamech Desktop") and the 
[embedded template client](https://github.com/diodelass/Teamech-Embedded-Template "Teamech Embedded Template").  

### Building
To build the Teamech server, follow these steps:  
1. Install an up-to-date stable distribution of Rust (per the Rust website, you can do this on most
Linux distributions by running `curl https://sh.rustup.rs -sSf | sh`).
2. Clone this repository (`git clone https://github.com/diodelass/Teamech-Server`) and `cd` into
the main directory (`cd Teamech-Server`).
3. Run `cargo build --release`.
4. The binary executable will be written to `Teamech-Server/target/release/teamech-server` where
it can be run or copied into a `bin/` directory to install it system-wide.  
  
### Additional Setup
In order to work, both the Teamech server and client must use a large symmetric key file, referred
to elsewhere as a pad file. In theory, any file will work as a pad file, but for optimal security,
the pad file should be generated using a secure random number generator.  
For optimal security, you should replace the pad file and install a new one on all of the network's 
devices every time the network exchanges a total of about half the pad file's size using that pad.
This is not operationally necessary, and there are currently no known vulnerabilities that would cause
failure to update the pads to allow an attacker to gain access to the system or decrypt its messages,
but by doing this, you ensure that you're at least a moving target should this change.  
Pad files should be large enough to be reasonably sure of including every possible byte at least once.
Practically, they should be as large as you can make them while still reasonably holding and transporting
them using the storage media you have available. A few megabytes is probably reasonable.  
On Linux, you can generate a pad file easily using `dd` and `/dev/urandom`. For instance, to create
a 10-megabyte pad:  
`dd if=/dev/urandom of=teamech-september-2018.pad bs=1M count=10 status=progress`  
You should then copy this pad file to the server and all clients, and select it as the pad file to
use at the command line.  
I make absolutely no guaratees about the security of any Teamech network, no matter what key size 
and key life cycle practices you adhere to. This software is a personal project to familiarize myself
with cryptography, network programming, and version control, and you shouldn't trust it in any context.
You probably shouldn't use it at all, but I can't stop you if you're determined.
  
### Mobile Support
A smartphone version of the Teamech client would be a useful tool for operating a Teamech network.
However, development of such an application is not currently on my roadmap, as I have no experience
developing for mobile platforms. At such time as this changes, there may eventually be an Android app
for Teamech. In the meantime, it is possible to compile and run the desktop client using an app such
as Termux that provides a Unix terminal environment, but this is obviously not very ergonomic.  
Clients targeting walled-garden platforms such as iOS are not planned and will not be seriously
considered at this time.

### Origin of Name
The name "Teamech" comes from a naïve and silly mishearing of a voice line from Overwatch, when
Brigitte activates her ultimate ability. The real line is "Alla till mig!" (Swedish: "Everyone to me!").
It doesn't really sound like "tea mech" even to the most obtuse American ear, but I guess I had bad 
speakers when I first played Overwatch.  
