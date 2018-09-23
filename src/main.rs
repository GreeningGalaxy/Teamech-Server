/* Teamech Server v0.6
 * August 2018
 * License: AGPL v3.0
 *
 * This source code is provided with ABSOLUTELY NO WARRANTY. You are fully responsible for any
* operations that your computers carry out as a result of running this code or anything derived
 * from it. The developer assumes the full absolution of liability described in the AGPL v3.0
 * license.
 *
 * OVERVIEW
 * Teamech is a simple, low-bandwidth supervisory control and data relay system intended for
 * internet-connected household appliances. Both clients and servers maintain security using a
 * strong encryption protocol, Teacrypt, for message secrecy and integrity verification. While 
 * this protocol is thought to be secure, neither the specification nor this implementation have
 * been formally verified, and as such should not be relied upon in life-or-death or otherwise
 * high-stakes situations.
 * Teamech is suitable for small-scale household use. As the server routes all packets to all
 * nodes, it does not scale well to very large systems, and is best deployed as a multi-drop
 * command delivery system to allow a single user client to control a small cluster of controller 
 * clients attached to the hardware being managed, using a server such as this one to relay
 * messages.
 * This file contains the source code for the Teamech server, which expects to communicate with
 * Teamech clients. 
 *
 *
 * Server Status Response Codes:
 * 
 * 0x02 START OF TEXT 
 *	  Subscription entered. Message received decrypted and verified successfully.
 *	  Client should now send identification.
 *
 * 0x03 END OF TEXT
 *	  Sent to a client instead of ACK when that client is the only subscriber on the server when
 *	  their message was sent. Message was validated and logged, but there was no one to send it
 *	  out to.
 *
 * 0x06 ACK
 *	  Message relay acknowledge - Packet was successfully rebroadcast to other subscribers.
 * 
 * 0x15 NAK 
 *	  Generic refusal - Packet was invalid (e.g. bad signature or timestamp) or inappropriate
 *	  (e.g. too short to be a valid encrypted payload).
 * 
 * 0x19 END OF MEDIUM 
 *	  Subscription invalidity notification. Regardless of previous state, client is now 
 *	  unsubscribed, and needs to re-subscribe by sending a valid encrypted payload if it wants to 
 *	  receive messages.
 * 
 * 0x1A SUBSTITUTE 
 *	  Server-side error notification. Client message may have been valid, but the server failed to 
 *	  process it correctly for an unrelated reason (e.g. pad file access error).
 *

Cargo.toml:
[package]
name = "teamech-server"
version = "0.6"
authors = ["ellie"]

[dependencies]
tiny-keccak = "1.4.2"
rand = "0.3"
dirs = "1.0.3"
chrono = "0.4"
byteorder = "1"
*/
		
extern crate tiny_keccak;
use tiny_keccak::Keccak;

extern crate rand;

extern crate dirs;
use dirs::home_dir;

extern crate chrono;
use chrono::prelude::*;

extern crate byteorder;
use byteorder::{LittleEndian,ReadBytesExt,WriteBytesExt};

use std::time::Duration;
use std::env::args;
use std::process;
use std::thread::sleep;
use std::error::Error;
use std::io;
use std::io::prelude::*;
use std::net::{UdpSocket,SocketAddr,IpAddr};
use std::collections::{HashMap,HashSet,VecDeque};
use std::fs;
use std::fs::File;
use std::path::{Path,PathBuf};

// Default Parameters
static MAX_PACKET_DELAY:i64 = 5_000;	// Maximum amount of time in the past or future a packet's timestamp can be in order to validate.
static MAX_BANNABLE_OFFENSES:u64 = 10;  // Maximum number of times a client can misstep before having their IP banned.
static MAX_DELIVERY_FAILURES:u64 = 5;   // Maximum number of times a client can fail to respond to a delivery before being dropped.
static LOG_DIRECTORY:&str = ".teamech-logs/server";

fn i64_bytes(number:&i64) -> [u8;8] {
	let mut bytes:[u8;8] = [0;8];
	match bytes.as_mut().write_i64::<LittleEndian>(*number) {
		Err(why) => {
			println!("FATAL: Could not convert integer to little-endian bytes: {}",why.description());
			process::exit(1);
		},
		Ok(_) => (),
	};
	return bytes;
}

fn u64_bytes(number:&u64) -> [u8;8] {
	let mut bytes:[u8;8] = [0;8];
	match bytes.as_mut().write_u64::<LittleEndian>(*number) {
		Err(why) => {
			println!("FATAL: Could not convert integer to little-endian bytes: {}",why.description());
			process::exit(1);
		},
		Ok(_) => (),
	};
	return bytes;
}

fn bytes_i64(bytes:&[u8;8]) -> i64 {
	return match bytes.as_ref().read_i64::<LittleEndian>() {
		Err(why) => {
			println!("FATAL: Could not convert little-endian bytes to integer: {}",why.description());
			process::exit(1);
		},
		Ok(n) => n,
	};
}

fn bytes_u64(bytes:&[u8;8]) -> u64 {
	return match bytes.as_ref().read_u64::<LittleEndian>() {
		Err(why) => {
			println!("FATAL: Could not convert little-endian bytes to integer: {}",why.description());
			process::exit(1);
		},
		Ok(n) => n,
	};
}

// bytes2hex converts a vector of bytes into a hexadecimal string. This is used mainly for
// debugging, when printing a binary string.
fn bytes2hex(v:&Vec<u8>) -> String {
	let mut result:String = String::from("");
	for x in 0..v.len() {
		if v[x] == 0x00 {
			result.push_str(&format!("00"));
		} else if v[x] < 0x10 {
			result.push_str(&format!("0{:x?}",&v[x]));
		} else {
			result.push_str(&format!("{:x?}",&v[x]));
		}
		if x < v.len()-1 {
			result.push_str(" ");
		}
	}
	return result;
}

// Takes a boolean expression and an input string, and returns whether the expression matches the
// input. 
// Example:
// input - @foo #foo #bar #baz
// pattern - @foo & !#bar
// result: false
// pattern - #bar | #bop
// result: true
fn wordmatch(pattern:&str,input:&str) -> bool {
	if pattern == "" || input.contains(&pattern) {
		// handle trivial cases, like empty patterns and patterns which match exactly one target,
		// prior to all others, ensuring that messages sent to all clients or single specified
		// names/classes are routed as fast as possible.
		return true;
	}
	let paddedinput:&str = &format!(" {} ",input);
	let ops:Vec<&str> = vec!["!","&","|","^","(",")"];
	let mut fixedpattern:String = String::from(pattern);
	for c in ops.iter() {
		fixedpattern = fixedpattern.replace(c,&format!(" {} ",c));
	}
	for element in fixedpattern.clone().split_whitespace() {
		let paddedelement:&str = &format!(" {} ",element);
		if !ops.contains(&element) {
			if paddedinput.contains(&paddedelement) {
				fixedpattern = fixedpattern.replace(&element,"1");
			} else {
				fixedpattern = fixedpattern.replace(&element,"0");
			}
		}
	}
	fixedpattern = fixedpattern.replace(" ","");
	loop {
		let mut subpattern:String = fixedpattern.clone();
		// NOT
		subpattern = subpattern.replace("!0","1");
		subpattern = subpattern.replace("!1","0");
		// OR
		subpattern = subpattern.replace("0|1","1");
		subpattern = subpattern.replace("1|0","1");
		subpattern = subpattern.replace("1|1","1");
		subpattern = subpattern.replace("0|0","0");
		// AND
		subpattern = subpattern.replace("0&1","0");
		subpattern = subpattern.replace("1&0","0");
		subpattern = subpattern.replace("1&1","1");
		subpattern = subpattern.replace("0&0","0");
		// XOR
		subpattern = subpattern.replace("0^1","1");
		subpattern = subpattern.replace("1^0","1");
		subpattern = subpattern.replace("1^1","0");
		subpattern = subpattern.replace("0^0","0");
		// Implied AND
		subpattern = subpattern.replace(")(","&");
		// Parens
		subpattern = subpattern.replace("(0)","0");
		subpattern = subpattern.replace("(1)","1");
		if subpattern == fixedpattern {
			break;
		}
		fixedpattern = subpattern;
	}
	if fixedpattern == "1" {
		return true;
	} else {
		return false;
	}
}

// Accepts a path to a log file, and writes a line to it, generating a human- and machine-readable log.
fn logtofile(logfilename:&Path,logstring:&str,timestamp:DateTime<Local>) -> Result<(),io::Error> {
	let userhome:PathBuf = match home_dir() {
		None => PathBuf::new(),
		Some(pathbuf) => pathbuf,
	};
	let logdir:&Path = &userhome.as_path().join(&LOG_DIRECTORY);
	match fs::create_dir_all(&logdir) {
		Err(why) => return Err(why),
		Ok(_) => (),
	};
	let logpath:&Path = &logdir.join(&logfilename);
	let mut logfile = match fs::OpenOptions::new() 
										.append(true)
										.open(&logpath) {
		Ok(file) => file,
		Err(why) => match why.kind() {
			io::ErrorKind::NotFound => match fs::File::create(&logpath) {
				Ok(file) => file,
				Err(why) => return Err(why),
			},
			_ => return Err(why),
		},
	};
	match writeln!(logfile,"[{}][{}] {}",timestamp.timestamp_millis(),timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),&logstring) {
		Ok(_) => return Ok(()),
		Err(why) => return Err(why),
	};
}

// Error-handling wrapper for logtofile() - rather than returning an error, prints the error
// message to the console and returns nothing.
fn log(logfilename:&Path,logstring:&str) {
	let timestamp:DateTime<Local> = Local::now();
	println!("[{}][{}] {}",timestamp.timestamp_millis(),timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),&logstring);
	match logtofile(&logfilename,&logstring,timestamp) {
		Err(why) => {
			println!("ERROR: Failed to write to log file at {}: {}",logfilename.display(),why.description());
		},
		Ok(()) => (),
	};
}

// Generates a single-use encryption key from a provided key size, pad file and authentication 
// nonce, and returns the key and its associated secret seed.
fn keygen(nonce:&[u8;8],pad:&Vec<u8>,keysize:&usize) -> (Vec<u8>,Vec<u8>) {
	// Finding the pad size this way won't work if the pad is a block device instead of a regular
	// file. If using the otherwise-valid strategy of using a filesystemless flash device as a pad,
	// this block will need to be extended to use a different method of detecting the pad size.
	let mut seed:[u8;8] = [0;8];
	let mut seednonce:[u8;8] = nonce.clone();
	let mut newseednonce:[u8;8] = [0;8];
	// Hash the nonce, previous hash, and previous byte retrieved eight times, using each hash to 
	// index one byte from the pad file. These eight bytes are the secret seed.
	// The hash is *truncated* to the first eight bytes (64 bits), then *moduloed* to the length of
	// the pad file. (If you try to decrypt by just moduloing the whole hash against the pad
	// length, it won't work.)
	for x in 0..8 {
		let mut sha3 = Keccak::new_sha3_256();
		sha3.update(&nonce.clone());
		sha3.update(&seednonce);
		if x >= 1 {
			sha3.update(&[seed[x-1]]);
		}
		sha3.finalize(&mut newseednonce);
		seednonce = newseednonce;
		seed[x] = pad[bytes_u64(&seednonce) as usize%pad.len()];
	}
	let mut keybytes:Vec<u8> = Vec::with_capacity(*keysize);
	let mut keynonce:[u8;8] = seed;
	let mut newkeynonce:[u8;8] = [0;8];
	// Hash the seed, previous hash, and previous byte retrieved n times, where n is the length of
	// the key to be generated. Use each hash to index bytes from the pad file (with the same
	// method as before). These bytes are the key.
	for x in 0..*keysize {
		let mut sha3 = Keccak::new_sha3_256();
		sha3.update(&seed);
		sha3.update(&keynonce);
		if x >= 1 {
			sha3.update(&[keybytes[x-1]]);
		}
		sha3.finalize(&mut newkeynonce);
		keynonce = newkeynonce;
		keybytes.push(pad[bytes_u64(&keynonce) as usize%pad.len()]);
	}
	return (keybytes,seed.to_vec());
}

// Depends on keygen function; generates a random nonce, produces a key, signs the message using
// the secret seed, and returns the resulting encrypted payload (including the message,
// signature, and nonce).
fn encrypt(message:&Vec<u8>,pad:&Vec<u8>) -> Vec<u8> {
	let nonce:u64 = rand::random::<u64>();
	let noncebytes:[u8;8] = u64_bytes(&nonce);
	let keysize:usize = message.len()+8;
	// Use the keygen function to create a key of length n + 8, where n is the length of the
	// message to be encrypted. (The extra eight bytes are for encrypting the signature.)
	let (keybytes,seed) = keygen(&noncebytes,&pad,&keysize);
	let mut signature:[u8;8] = [0;8];
	let mut sha3 = Keccak::new_sha3_256();
	// Generate the signature by hashing the secret seed, the unencrypted message, and the key used
	// to encrypt the signature and message. 
	sha3.update(&seed);
	sha3.update(&message);
	sha3.update(&keybytes);
	sha3.finalize(&mut signature);
	let mut verimessage = Vec::new();
	verimessage.append(&mut message.clone());
	verimessage.append(&mut signature.to_vec());
	let mut payload = Vec::new();
	for x in 0..keysize {
		payload.push(verimessage[x] ^ keybytes[x]);
	}
	payload.append(&mut noncebytes.to_vec());
	return payload;
}

// Depends on keygen function; uses the nonce attached to the payload to generate the same key and
// secret seed, decrypt the payload, and verify the resulting message with its signature. The
// signature will only validate if the message was the original one encrypted with the same pad 
// file as the one used to decrypt it; if it has been tampered with, generated with a different
// pad, or is just random junk data, the validity check will fail and this function will return an
// io::ErrorKind::InvalidData error.
fn decrypt(payload:&Vec<u8>,pad:&Vec<u8>) -> (bool,Vec<u8>) {
	let mut noncebytes:[u8;8] = [0;8];
	// Detach the nonce from the payload, and use it to generate the key and secret seed.
	noncebytes.copy_from_slice(&payload[payload.len()-8..payload.len()]);
	let keysize = payload.len()-8;
	let ciphertext:Vec<u8> = payload[0..payload.len()-8].to_vec();
	let (keybytes,seed) = keygen(&noncebytes,&pad,&keysize);
	let mut verimessage = Vec::new();
	// Decrypt the message and signature using the key.
	for x in 0..keysize {
		verimessage.push(ciphertext[x] ^ keybytes[x]);
	}
	let mut signature:[u8;8] = [0;8];
	// Detach the signature from the decrypted message, and use it to verify the integrity of the
	// message. If the check succeeds, return Ok() containing the message content; if it fails,
	// return an io::ErrorKind::InvalidData error.
	signature.copy_from_slice(&verimessage[verimessage.len()-8..verimessage.len()]);
	let message:Vec<u8> = verimessage[0..verimessage.len()-8].to_vec();
	let mut truesig:[u8;8] = [0;8];
	let mut sha3 = Keccak::new_sha3_256();
	sha3.update(&seed);
	sha3.update(&message);
	sha3.update(&keybytes);
	sha3.finalize(&mut truesig);
	return (signature == truesig,message);
}

// Sends a vector of bytes to a specific host over a specific socket, automatically retrying in the event of certain errors
// and aborting in the event of others.
fn sendraw(listener:&UdpSocket,destaddr:&SocketAddr,payload:&Vec<u8>) -> Result<(),io::Error> {
	// loop until either the send completes or an unignorable error occurs.
	loop {
		match listener.send_to(&payload[..],destaddr) {
			Ok(nsend) => match nsend < payload.len() {
				// If the message sends in its entirety, exit with success. If it sends
				// incompletely, try again.
				false => return Ok(()),
				true => (),
			},
			Err(why) => match why.kind() {
				// Interrupted just means we need to try again.
				// WouldBlock for a send operation usually means that the transmit buffer is full.
				io::ErrorKind::Interrupted => (),
				io::ErrorKind::WouldBlock => {
					println!("{} Error: failed to send byte - transmit buffer overflow!",Local::now().format("%Y-%m-%d %H:%M:%S"));
					return Err(why);
				},
				_ => {
					println!("{} Error: failed to send byte - {}",Local::now().format("%Y-%m-%d %H:%M:%S"),why.description());
					return Err(why);
				},
			},
		};
	}
}

// Automatically encrypts a vector of bytes and sends them over the socket.
fn sendbytes(listener:&UdpSocket,destaddr:&SocketAddr,bytes:&Vec<u8>,pad:&Vec<u8>) -> Result<(),io::Error> {
	let mut stampedbytes = bytes.clone();
	stampedbytes.append(&mut i64_bytes(&Local::now().timestamp_millis()).to_vec());
	let payload = encrypt(&stampedbytes,&pad); 
	return sendraw(&listener,&destaddr,&payload);
}

#[derive(Clone)]
struct Subscription {
	name:String,
	classes:Vec<String>,
	lastact:i64,
	pendingack:bool,
	deliveryfailures:u64,
}

fn main() {
	let argv:Vec<String> = args().collect();
	if argv.len() != 3 {
		// If the user provided some number of arguments other than 2, it probably means they don't
		// know how this program works and need to be reminded.
		println!("Usage: teamech [port] [padfile]");
		process::exit(1);
	}
	let portn:u16;
	if let Ok(n) = argv[1].parse::<u16>() {
		if n > 0 {
			// If this looks like a valid 16-bit int, set it as the port number.
			portn = n;
		} else {
			// If the user asked for port 0, tell them all about why that won't go and what we're doing
			// instead of passing 0 to the OS.
			print!("Port 0 (OS auto-select) has been provided. Autoselection of port numbers is not supported for the server ");
			print!("by the Teamech protocol, so port 6666 (the Teamech default) has been selected. If you try to run two instances of ");
			print!("Teamech with port 0 specified for both, it will NOT work - if you want to run more than one Teamech server at a ");
			print!("time, you *need* to specify the ports for each manually.");
			println!();
			portn = 6666;
		}
	} else {
		// If the user provided something that won't parse as a u16, remind them of usage, gripe,
		// and then quit, because that won't do.
		println!("Usage: teamech [port] [padfile]");
		println!("Could not parse first argument as a port number. Expected an integer between 0 and 65536.");
		process::exit(1);
	}

	let logfilename:String = format!("{}-teamech-server.log",&Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
	let logfile:&Path = Path::new(&logfilename);
	let padpath:&Path = Path::new(&argv[2]);	
	// Spam detection and auth equipment. 
	let mut banpoints:HashMap<IpAddr,u64> = HashMap::new();
	let mut bannedips:HashSet<IpAddr> = HashSet::new();
	// Recovery loop: if an unignorable error occurs that requires restarting, we can `break` the inner loops
	// to wait a set delay before restarting, or `continue` the 'recovery loop to restart immediately.
	'recovery:loop {
		match logtofile(&logfile,&format!("Opening of log file"),Local::now()) {
			Err(why) => {
				println!("WARNING: Could not open log file at {} - {}. Logs are currently NOT BEING SAVED - you should fix this!",
																								&logfile.display(),&why.description());
			},
			Ok(_) => (),
		};
		// Load the entire pad file into memory. Previous versions did not do this and attempted to
		// save memory space by accessing storage every time encryption was carried out, but the
		// performance losses resulting from this vastly outweight saving ~10 MB of system memory.
		// We live in a world where a chat app can take up 200 MB under normal run conditions and
		// no one bats an eye, so I'm just going to assume that this is fine.
		log(&logfile,&format!("Loading pad file from {}...",&padpath.display()));
		let mut pad:Vec<u8> = Vec::new();
		match File::open(&padpath) {
			Err(why) => {
				log(&logfile,&format!("Crash due to local failure to open pad file at {}: {}",&padpath.display(),&why.description()));
				process::exit(1);
			},
			Ok(mut padfile) => match padfile.read_to_end(&mut pad) {
				Err(why) => {
					log(&logfile,&format!("Crash due to local failure to load key data from pad file at {}: {}",&padpath.display(),&why.description()));
					process::exit(1);
				},
				Ok(_) => {
					log(&logfile,&format!("Successful load of key data from pad file"));
				},
			},
		};
		let mut inbin:[u8;500]; // recv buffer. payloads longer than 500 bytes will be truncated!
		let mut subscriptions:HashMap<SocketAddr,Subscription> = HashMap::new(); // directory of subscribed addresses and delivery failures
		let listener:UdpSocket = match UdpSocket::bind(&format!("0.0.0.0:{}",&portn)) {
			Ok(socket) => socket,
			Err(why) => {
				// Fatal error condition #1: We can't bind to the local address on the given UDP
				// port. Something's probably blocking it, which the user will need to clear before
				// this program can run.
				log(&logfile,&format!("Crash due to local failure to bind to local address: {}",&why.description()));
				process::exit(1);
			},
		};
		log(&logfile,&format!("Successful opening of socket on port {}",&portn));
		/*match listener.set_nonblocking(true) {
			Ok(_) => (),
			Err(why) => {
				// Fatal error condition #2: We can't set the UDP socket to non-blocking mode,
				// meaning the program won't really work. It's unclear to me what would cause this,
				// but it would probably be a platform compatibility-related error, and not
				// something we can fix here.
				log(&logfile,&format!("Crash due to local failure to get non-blocking read access from the socket: {}",&why.description()));
				process::exit(1);
			},
		};*/
		// Processor loop: When the server is running nominally, this never breaks. Error
		// conditions requiring the system to be reset (e.g. loss of connectivity) can break the
		// loop, and execution will be caught by the recovery loop and returned to the top.
		log(&logfile,&format!("Completion of startup sequence"));
		let mut inqueue:VecDeque<(SocketAddr,Vec<u8>)> = VecDeque::new();
		'processor:loop {
			//sleep(Duration::new(0,1_000_000));
			inbin = [0;500];
			match listener.recv_from(&mut inbin) {
				Ok((nrecv,srcaddr)) => {
					let _ = inqueue.push_back((srcaddr,inbin[0..nrecv].to_vec()));
				}
				Err(why) => match why.kind() {
					// Receiving from the UdpSocket failed for some reason. 
					io::ErrorKind::WouldBlock => (), // Nothing in the receive buffer; we'll come back later.
					io::ErrorKind::Interrupted => (), // Something stopped us in the middle of the operation, so I guess we'll try again later?
					_ => {
						// A real error happened, which is a problem. Maybe the OS nixed our socket
						// binding, or the network is borked? I dunno, but since this server is
						// supposed to run unsupervised, we'll just let the recovery loop catch us
						// and try to start again, rather than exiting. 
						log(&logfile,&format!("Local read error on socket: {}",&why.description()));
						break 'processor;
					},
				},
			}; // match recvfrom
			for sub in subscriptions.iter_mut() {
				if sub.1.pendingack && sub.1.lastact+MAX_PACKET_DELAY*2 < Local::now().timestamp_millis() {
					log(&logfile,&format!("Delivery failure to @{}/#{} [{}] [{} failures so far]",
																							&sub.1.name,&sub.1.classes[0],&sub.0,&sub.1.deliveryfailures+1));
					sub.1.deliveryfailures += 1;
					sub.1.pendingack = false;
				} 
			}
			for sub in subscriptions.clone().iter() {
				if sub.1.deliveryfailures > MAX_DELIVERY_FAILURES {
					log(&logfile,&format!("Termination of subscription for @{}/#{} [{}] for exceeding {} delivery failures",
																								&sub.1.name,&sub.1.classes[0],&sub.0,&MAX_DELIVERY_FAILURES));
					let _ = subscriptions.remove(&sub.0);
					let _ = sendbytes(&listener,&sub.0,&vec![0x19],&pad); // END OF MEDIUM
				}
			}
			match inqueue.pop_front() {
				Some((srcaddr,recvdata)) => {
					// First make sure the sender is not banned.
					// It is important to do this as early as possible to minimize the impact of an
					// ongoing DoS attack. 
					if bannedips.contains(&srcaddr.ip()) {
						continue 'processor;
					} else if let Some(n) = banpoints.get(&srcaddr.ip()) {
						// If the sender is not already banned, next check if they are a known offender
						// who needs to be banned. This is a very slightly more costly operation than
						// checking bans, but is still pretty lightweight and can safely be done here.
						if *n > MAX_BANNABLE_OFFENSES {
							let _ = bannedips.insert(srcaddr.ip());
							let _ = subscriptions.remove(&srcaddr);
							continue 'processor;
						}
					} 
					// If we have no records on this sender, add an entry to the banpoints ledger
					// for them to keep track of their behavior.
					if !banpoints.contains_key(&srcaddr.ip()) {
						let _ = banpoints.insert(srcaddr.ip(),0);
					}
					if recvdata.len() < 24 { 
						// 24 is the minimum size of valid encrypted packet: 0 message bytes, 
						// 8 timestamp bytes, 8 signature bytes, 8 nonce bytes. 
						// Messages of length less than this cannot be decrypted, so we can't
						// validate them, and won't relay them to clients.
						// This is not a bannable offense, because there's a chance it's due to
						// some type of send or receive error and not an evil client.
						let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&pad); // NAK
						if let Some(points) = banpoints.get_mut(&srcaddr.ip()) {
							*points += 1;
						}
						continue 'processor;
					}
					// If we've come this far, it means the message is a valid payload for
					// decryption and comes from a subscribed and authenticated sender. It's time
					// to try decrypting it, so we can verify it for integrity and log its payload.
					let (datavalid,stampedmessage):(bool,Vec<u8>) = decrypt(&recvdata,&pad);
					let message:Vec<u8> = stampedmessage[0..stampedmessage.len()-8].to_vec();
					if !datavalid {
						log(&logfile,&format!("Invalid packet from client at {} (contents: '{}'), subscription terminated",
																					&srcaddr,String::from_utf8_lossy(&message)));
						let _ = sendbytes(&listener,&srcaddr,&vec![0x19],&pad); // END OF MEDIUM
						let _ = subscriptions.remove(&srcaddr);
						if let Some(points) = banpoints.get_mut(&srcaddr.ip()) {
							*points += 1;
						}
						continue 'processor;
					}
					let mut sendername:String = String::from("unknown");
					let mut senderclasses:Vec<String> = vec![String::from("unknown")];
					if let Some(sub) = subscriptions.get(&srcaddr) {
						sendername = sub.name.clone();
						senderclasses = sub.classes.clone();
					}
					// Reaching this point means the message decrypted and validated successfully.
					// However, we still need to verify the timestamp to make sure this isn't a
					// replay attack.
					let mut timestamp:[u8;8] = [0;8];
					timestamp.copy_from_slice(&stampedmessage[stampedmessage.len()-8..stampedmessage.len()]);
					let inttimestamp:i64 = bytes_i64(&timestamp);
					if inttimestamp > Local::now().timestamp_millis()+MAX_PACKET_DELAY {
						// Packet timestamp more than the allowed delay into the future? This is a
						// very weird and unlikely case, probably a clock sync error and not an
						// attack, but we'll reject it anyway just to be on the safe side.
						log(&logfile,&format!("Packet rejection to @{}/#{} [{}] due to future timestamp [{} ms]",
													&sendername,&senderclasses[0],&srcaddr,&inttimestamp-&Local::now().timestamp_millis()));
						let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&pad); // NAK
						continue 'processor;
					} else if Local::now().timestamp_millis() > inttimestamp+MAX_PACKET_DELAY {
						// This is the most likely situation in an actual replay attack - the
						// timestamp is too far in the past. This means we need to reject the
						// packet, since it could be used to confuse clients maliciously.
						log(&logfile,&format!("Packet rejection to @{}/#{} [{}] due to past timestamp [{} ms]",
													&sendername,&senderclasses[0],&srcaddr,&Local::now().timestamp_millis()-&inttimestamp));
						let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&pad); // NAK
						continue 'processor;
					}
					// By this point, the packet is fully verified and can be retransmitted. 
					if !subscriptions.contains_key(&srcaddr) {
						// Let the sender know that they were subscribed if they weren't already
						let _ = sendbytes(&listener,&srcaddr,&vec![0x02],&pad); // START OF TEXT
						log(&logfile,&format!("Establishment of subscription for client at {}",&srcaddr));
					}
					// Insert the new subscription, or reset the sender's existing subscription 
					// status to keep it current.
					if let Some(sub) = subscriptions.get_mut(&srcaddr) {
						if sub.deliveryfailures > 0 {
							log(&logfile,&format!("Reset of delivery failure count for @{}/#{} [{}] from {}",
													&sendername,&senderclasses[0],&srcaddr,&sub.deliveryfailures));
						}
						sub.lastact = Local::now().timestamp_millis();
						sub.pendingack = false;
						sub.deliveryfailures = 0;
					}
					if !subscriptions.contains_key(&srcaddr) {
						let _ = subscriptions.insert(srcaddr,
							Subscription{
								name:String::new(),
								classes:vec![String::new()],
								lastact:Local::now().timestamp_millis(),
								pendingack:false,
								deliveryfailures:0	
							}
						);
					}
					if message.len() == 0 {
						// If this is an empty message, don't bother relaying it. These types of
						// messages can be used as subscription requests.
						let _ = sendbytes(&listener,&srcaddr,&vec![0x06],&pad); // START OF TEXT
						continue 'processor;
					}
					// Payloads containing a message which is a single byte and one of the ASCII 
					// non-printing control characters are reserved for client-server functions. 
					if (message.len() == 1 && message[0] <= 0x1F) || (message.len() >= 2 && (message[0] == 0x01 || message[0] == 0x11)) {
						match message[0] {
							0x01 => { // START OF HEADING
								// Client is telling us its semiunique name.
								let newname:String = String::from_utf8_lossy(&message[1..message.len()].to_vec()).to_string();
								for c in ['@','#','&','|',' ','!','^'].iter() {
									if newname.contains(*c) {
										log(&logfile,&format!("Client name declaration of '{}' from client at {} - invalid (contains illegal characters)",
																																	&newname,&srcaddr));
										let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&pad); // NAK
										continue 'processor;
									}
								}
								if let Some(sub) = subscriptions.get_mut(&srcaddr) {
									if newname.len() > 128 {
										log(&logfile,&format!("Client name declaration of '{}' from client at {} - invalid (too long)",&newname,&srcaddr));
										let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&pad); // NAK
									} else {
										log(&logfile,&format!("Client name declaration of '{}' from client at {}",&newname,&srcaddr));
										sub.name = newname;
										let _ = sendbytes(&listener,&srcaddr,&vec![0x06],&pad); // ACK
									} 
								} else {
									log(&logfile,&format!("Client name declaration of '{}' from unregistered client at {}",&newname,&srcaddr));
									let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&pad); // NAK
								}
							},
							0x11 => { // DEVICE CONTROL ONE
								// Client is telling us a nonunique device class by which it can be
								// addressed.
								let newclass:String = String::from_utf8_lossy(&message[1..message.len()].to_vec()).to_string();
								for c in ['@','#','&','|',' ','!','^'].iter() {
									if newclass.contains(*c) {
										log(&logfile,&format!("Client class declaration of '{}' from client at {} - invalid (contains illegal characters)",
																														&newclass,&srcaddr));
										let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&pad); // NAK
										continue 'processor;
									}
								}
								if let Some(sub) = subscriptions.get_mut(&srcaddr) {
									if newclass.len() > 128 {
										log(&logfile,&format!("Clientclass declaration of '{}' from client at {} - invalid (too long)",&newclass,&srcaddr));
										let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&pad); // NAK
									} else {
										log(&logfile,&format!("Client class declaration of '{}' from client at {}",&newclass,&srcaddr));
										if sub.classes == vec![String::new()] {
											sub.classes = Vec::new();
										}
										if !sub.classes.contains(&newclass) {
											sub.classes.push(newclass);
										}
										let _ = sendbytes(&listener,&srcaddr,&vec![0x06],&pad); // ACK
									}
								}
							},
							0x12 => { // DEVICE CONTROL TWO
								// Client is revoking a class that was previously set.
								let delclass:String = String::from_utf8_lossy(&message[1..message.len()].to_vec()).to_string();
								if let Some(sub) = subscriptions.get_mut(&srcaddr) {
									for n in (0..sub.classes.len()).rev() {
										if sub.classes[n] == delclass {
											sub.classes.remove(n);
										}
									}
									let _ = sendbytes(&listener,&srcaddr,&vec![0x06],&pad); // ACK
								} 
							},
							0x05 => { // ENQUIRY
								// Client is asking us who else is on the server.
								log(&logfile,&format!("Request for subscription list by @{}/#{} [{}]",&sendername,&senderclasses[0],&srcaddr));
								for sub in subscriptions.values() {
									for class in &sub.classes {
										let mut subline:Vec<u8> = Vec::new();
										subline.push(0x05);
										subline.append(&mut sub.name.as_bytes().to_vec());
										subline.push(0x09);
										subline.append(&mut class.as_bytes().to_vec());
										let _ = sendbytes(&listener,&srcaddr,&subline,&pad);
									}
								}
								log(&logfile,&format!("Complete transmission of subscription list to @{}/#{} [{}]",&sendername,&senderclasses[0],&srcaddr));
							},
							0x18 => { // CANCEL
								// Subscription cancellation: The sender has notified us that they
								// are no longer listening and we should stop sending them stuff.
								// Whenever a subscription is cancelled for any reason, we send END
								// OF MEDIUM; the client can react to this however they like. 
								log(&logfile,&format!("Cancellation of subscription by @{}/#{} [{}]",&sendername,&senderclasses[0],&srcaddr));
								let _ = subscriptions.remove(&srcaddr);
								let _ = sendbytes(&listener,&srcaddr,&vec![0x19],&pad); // END OF MEDIUM
							},
							0x06 => {
								if let Some(sub) = subscriptions.get_mut(&srcaddr) {
									sub.pendingack = false;
									sub.lastact = Local::now().timestamp_millis();
								} else {
									let _ = sendbytes(&listener,&srcaddr,&vec![0x19],&pad); // END OF MEDIUM
								}
							},
							0x15 => (), // client didn't like that? ok.
							other => {
								// Unimplemented control code? NAK response for now.
								log(&logfile,&format!("Unknown control packet {} from @{}/#{} [{}]",
																			&bytes2hex(&vec![other]),&sendername,&senderclasses[0],&srcaddr));
								let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&pad); // NAK
							},
						}; // match recvdata[0]
						continue 'processor;
					}
					let stringmessage:String = String::from_utf8_lossy(&message).to_string();
					log(&logfile,&format!("@{}/#{} [{}] -> {} [0x {}]",&sendername,&senderclasses[0],&srcaddr,&stringmessage,bytes2hex(&message)));
					let mut destpattern:&str = "";
					if message[0] == b'>' {
						destpattern = stringmessage.splitn(2," ").collect::<Vec<&str>>()[0].trim_left_matches('>');
						log(&logfile,&format!("Message routing to {}",destpattern));
					}
					let mut relayline:Vec<u8> = format!("@{}/#{} ",&sendername,&senderclasses[0]).as_bytes().to_vec();
					relayline.append(&mut message.clone());
					relayline.append(&mut i64_bytes(&Local::now().timestamp_millis()).to_vec());
					let relaypayload:Vec<u8> = encrypt(&relayline,&pad);
					// Produce a table of subscribers other than the sender, to which to send the
					// message.
					let mut othersubs:HashMap<SocketAddr,Subscription> = subscriptions.clone();
					let _ = othersubs.remove(&srcaddr);
					let mut retransmissions:u64 = 0;
					'itersend:for sub in othersubs.iter() {
						// send the message to clients with the specified name or class, or send to
						// everyone if no name or class was specified.
						let subattrs:&str = &format!("@{} #{}",sub.1.name,sub.1.classes.join(" #"));
						if wordmatch(&destpattern,&subattrs) || (sub.1.classes.contains(&"supervisor".to_owned())) {
							match sendraw(&listener,&sub.0,&relaypayload) {
								Err(why) => {
									log(&logfile,&format!("Local failure to transmit packet to {}: {}",&sub.0,&why.description()));
								},
								Ok(_) => {
									if let Some(sub) = subscriptions.get_mut(&sub.0) {
										if !sub.pendingack {
											sub.pendingack = true;
											sub.lastact = Local::now().timestamp_millis();
										}
									}
									retransmissions += 1;
								},
							};
						}
					} // 'itersend
					log(&logfile,&format!("Retransmission to {} clients",&retransmissions));
					if retransmissions > 0 {
						let _ = sendbytes(&listener,&srcaddr,&vec![0x06],&pad); // ACK
					} else {
						// If there is no one else on the server, let the client know by
						// responding with 0x03 END OF TEXT instead of 0x06 ACK.
						let _ = sendbytes(&listener,&srcaddr,&vec![0x03],&pad); // END OF TEXT
					}
				}, // pop Some
				None => {
					sleep(Duration::new(0,10_000_000));
				},
			}; // match inqueue.pop_front()
			// Time delay for the processor is handled at the top, not here, so that `continue`
			// operations will still use the time delay.
		} // 'processor
		sleep(Duration::new(1,0));
	} // 'recovery
}
