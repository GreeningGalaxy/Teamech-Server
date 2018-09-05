/* Teamech Server v0.3
 * August 2018
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
 * Teamech clients. The distribution in which you received this file should also contain the source
 * code for the desktop client.
*/

/* Server Control Response Codes:
 * 0x01 START OF HEADING - Authentication request response; contains eight-byte authentication nonce
 *					  as payload.
 * 0x02 START OF TEXT - Authentication success. Password/nonce hash received matched correct value.
 * 0x06 ACK - Generic acknowledge - Packet was successfully rebroadcast to other subscribers.
 * 0x15 NAK - Generic refusal - Packet was invalid (e.g. bad signature or timestamp) or inappropriate.
 * 0x16 SYNCHRONOUS IDLE -	Response to client sending the same; indicates that the client's
 *							subscription was renewed successfully.
 * 0x19 END OF MEDIUM - Subscription invalidity notification. Client needs to re-authenticate
 *						before sending additional data.
 * 0x1A SUBSTITUTE - Server-side error notification. Client message may have been valid, but server
 *					 failed to process it correctly for an unrelated reason (e.g. pad file access
 *					 error).
 *
*/
	
extern crate tiny_keccak;
use tiny_keccak::Keccak;
extern crate rand;
use std::env::args;
use std::process;
use std::time::{Duration,SystemTime,UNIX_EPOCH};
use std::thread::sleep;
use std::error::Error;
use std::io;
use std::io::prelude::*;
use std::net::{UdpSocket,SocketAddr,IpAddr};
use std::collections::{HashMap,HashSet};
use std::fs;
use std::path::Path;

// Default Parameters
static CONNECT_TIMEOUT:u64 = 300_000;	// Maximum amount of time a client can remain inactive before being automatically unsubscribed
static MAX_PACKET_DELAY:u64 = 10_000;   // Maximum amount of time in the past a packet's timestamp can be in order to validate.

// systime function; gets the unixtime in milliseconds.
fn systime() -> u64 {
	match SystemTime::now().duration_since(UNIX_EPOCH) {
		Ok(time) => {
			return time.as_secs()*1_000 + (time.subsec_nanos() as u64)/1_000_000 ;
		},
		Err(why) => {
			// If there's a problem getting the system time (probably a platform thing) then this
			// is going to return 0, which corresponds to midnight on January 1st, 1970. Watch out!
			println!("Error while getting system time: {}",why.description());
			return 0;
		},
	};
}

// int2bytes takes a single 64-bit int and converts it into an array of eight bytes. I'm pretty
// sure this should actually work consistently between endiannesses, but Teamech won't interoperate
// between systems of different endianness without platform-specific modification. (Teamech
// messages always operate in little endian.)
fn int2bytes(n:&u64) -> [u8;8] {
	let mut result:[u8;8] = [0;8];
	for i in 0..8 {
		result[7-i] = (0xFF & (*n >> i*8)) as u8;
	}
	return result;
}

// bytes2int is, unsurprisingly, the inverse function of int2bytes, which takes an array of 8 bytes
// and converts it into a single 64-bit int. The same endianness considerations as above apply.
fn bytes2int(b:&[u8;8]) -> u64 {
	let mut result:u64 = 0;
	for i in 0..8 {
		result += (b[i] as u64)*2u64.pow(((7-i) as u32)*8u32);
	}
	return result;
}

// bytes2hex converts a vector of bytes into a hexadecimal string. This is used mainly for
// // debugging, when printing a binary string.
fn bytes2hex(v:&Vec<u8>) -> String {
	let mut result:String = String::from("0x");
	for x in 0..v.len() {
		if v[x] == 0x00 {
			result.push_str(&format!("00"));
		} else if v[x] < 0x10 {
			result.push_str(&format!("0{:x?}",v[x]));
		} else {
			result.push_str(&format!("{:x?}",v[x]));
		}
	}
	return result;
}

// Generates a single-use encryption key from a provided key size, pad file and authentication 
// nonce, and returns the key and its associated secret seed.
fn keygen(nonce:&[u8;8],padpath:&Path,keysize:&usize) -> Result<(Vec<u8>,Vec<u8>),io::Error> {
	let mut padfile:fs::File = match fs::File::open(&padpath) {
		Err(e) => return Err(e),
		Ok(file) => file,
	};
	// Finding the pad size this way won't work if the pad is a block device instead of a regular
	// file. If using the otherwise-valid strategy of using a filesystemless flash device as a pad,
	// this block will need to be extended to use a different method of detecting the pad size.
	let padsize:u64 = match fs::metadata(&padpath) {
		Err(e) => return Err(e),
		Ok(metadata) => metadata.len(),
	};
	let mut inbin:[u8;1] = [0];
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
		let _ = padfile.seek(io::SeekFrom::Start(bytes2int(&seednonce) % padsize));
		let _ = padfile.read_exact(&mut inbin);
		seed[x] = inbin[0];
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
		let _ = padfile.seek(io::SeekFrom::Start(bytes2int(&keynonce) % padsize));
		let _ = padfile.read_exact(&mut inbin);
		keybytes.push(inbin[0]);
	}
	return Ok((keybytes,seed.to_vec()));
}

// Depends on keygen function; generates a random nonce, produces a key, signs the message using
// the secret seed, and returns the resulting encrypted payload (including the message,
// signature, and nonce).
fn encrypt(message:&Vec<u8>,padpath:&Path) -> Result<Vec<u8>,io::Error> {
	let nonce:u64 = rand::random::<u64>();
	let noncebytes:[u8;8] = int2bytes(&nonce);
	let keysize:usize = message.len()+8;
	// Use the keygen function to create a key of length n + 8, where n is the length of the
	// message to be encrypted. (The extra eight bytes are for encrypting the signature.)
	let (keybytes,seed) = match keygen(&noncebytes,&padpath,&keysize) {
		Ok((k,s)) => (k,s),
		Err(e) => return Err(e),
	};
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
	return Ok(payload);
}

// Depends on keygen function; uses the nonce attached to the payload to generate the same key and
// secret seed, decrypt the payload, and verify the resulting message with its signature. The
// signature will only validate if the message was the original one encrypted with the same pad 
// file as the one used to decrypt it; if it has been tampered with, generated with a different
// pad, or is just random junk data, the validity check will fail and this function will return an
// io::ErrorKind::InvalidData error.
fn decrypt(payload:&Vec<u8>,padpath:&Path) -> Result<Vec<u8>,io::Error> {
	let mut noncebytes:[u8;8] = [0;8];
	// Detach the nonce from the payload, and use it to generate the key and secret seed.
	noncebytes.copy_from_slice(&payload[payload.len()-8..payload.len()]);
	let keysize = payload.len()-8;
	let ciphertext:Vec<u8> = payload[0..payload.len()-8].to_vec();
	let (keybytes,seed) = match keygen(&noncebytes,&padpath,&keysize) {
		Ok((k,s)) => (k,s),
		Err(e) => return Err(e),
	};
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
	let mut rightsum:[u8;8] = [0;8];
	let mut sha3 = Keccak::new_sha3_256();
	sha3.update(&seed);
	sha3.update(&message);
	sha3.update(&keybytes);
	sha3.finalize(&mut rightsum);
	if signature == rightsum {
		return Ok(message);
	} else {
		return Err(io::Error::new(io::ErrorKind::InvalidData,"Payload signature verification failed"));
	}
}

// Sends a vector of bytes to a specific host over a specific socket, automatically retrying in the event of certain errors
// and aborting in the event of others.
fn sendbytes(listener:&UdpSocket,destaddr:&SocketAddr,bytes:&Vec<u8>) -> Result<(),io::Error> {
	// loop until either the send completes or an unignorable error occurs.
	loop {
		match listener.send_to(&bytes[..],destaddr) {
			Ok(nsend) => match nsend < bytes.len() {
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
					println!("Error: failed to send byte - transmit buffer overflow!");
					return Err(why);
				},
				_ => {
					println!("Error: failed to send byte - {}",why.description());
					return Err(why);
				},
			},
		};
	}
}

// Same as sendbytes, but loops until not only the send is successful, but also until a specific
// payload is returned from the destination. There is both a timeout and a maximum number of tries
// before which the function will give up and return an io::ErrorKind::NotFound error.
fn sendbytesuntil(listener:&UdpSocket,destaddr:&SocketAddr,bytes:&Vec<u8>,target:&Vec<u8>,timeout:&u32,tries:&u32) -> Result<(),io::Error> {
	let mut inbin:[u8;500] = [0;500];
	'trier:for _x in 0..*tries {
		// Attempt to send bytes normally; if an error is raised, propagate it and exit.
		match sendbytes(&listener,&destaddr,&bytes) {
			Ok(()) => (),
			Err(e) => return Err(e),
		};
		// Wait for a payload to be received from the destination address. 
		sleep(Duration::new(0,(timeout/tries)*1_000_000));
		match listener.recv_from(&mut inbin) {
			Ok((nrecv,srcaddr)) => {
				if &srcaddr == destaddr && inbin[0..nrecv] == target[..] {
					return Ok(());
				}
			},
			// Handle non-fatal errors such as WouldBlock or Interrupted by just starting the
			// next try. Other errors are propagated out.
			Err(why) => match why.kind() {
				io::ErrorKind::WouldBlock => (),
				io::ErrorKind::Interrupted => (),
				_ => return Err(why),
			},
		};
	}
	return Err(io::Error::new(io::ErrorKind::NotFound,"Specified data payload was not found"));
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
			print!("Warning: Port 0 (OS auto-select) has been provided. Autoselection of port numbers is not supported for the server by the Teamech protocol, ");
			print!("so port 6666 (the Teamech default) has been selected. If you try to run two instances of Teamech with port 0 specified for both, it will ");
			print!("NOT work - if you want to run more than one Teamech server at a time, you *need* to specify the ports for each manually.");
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
	let padpath:&Path = Path::new(&argv[2]);	
	// Spam detection and auth equipment. 
	let mut banpoints:HashMap<IpAddr,u64> = HashMap::new();
	let mut bannedips:HashSet<IpAddr> = HashSet::new();
	let mut nonces:HashMap<SocketAddr,(Vec<u8>,Vec<u8>,Vec<u8>)> = HashMap::new(); // (noncevalue,challengenonce,responsenonce)
	// Recovery loop: if an unignorable error occurs that requires restarting, we can `break` the inner loops
	// to wait a set delay before restarting, or `continue` the 'recovery loop to restart immediately.
	'recovery:loop {
		match fs::File::open(&padpath) {
			Err(why) => {
				println!("Could not open specified pad file - {}",why.description());
				process::exit(1);
			},
			Ok(_) => {
				println!("Initialized pad file.");
			},
		};
		let mut inbin:[u8;500]; // recv buffer. payloads longer than 500 bytes will be truncated!
		let mut reggs:HashMap<SocketAddr,u64> = HashMap::new(); // directory of subscribed addresses
		let listener:UdpSocket = match UdpSocket::bind(&format!("0.0.0.0:{}",portn)) {
			Ok(socket) => socket,
			Err(why) => {
				// Fatal error condition #1: We can't bind to the local address on the given UDP
				// port. Something's probably blocking it, which the user will need to clear before
				// this program can run.
				println!("Could not bind to local address: {}",why.description());
				process::exit(1);
			},
		};
		println!("Opened socket on port {}.",portn);
		match listener.set_nonblocking(true) {
			Ok(_) => (),
			Err(why) => {
				// Fatal error condition #2: We can't set the UDP socket to non-blocking mode,
				// meaning the program won't really work. It's unclear to me what would cause this,
				// but it would probably be a platform compatibility-related error, and not
				// something we can fix here.
				println!("Could not set socket to nonblocking mode: {}",why.description());
				process::exit(1);
			},
		};
		// Processor loop: When the server is running nominally, this never breaks. Error
		// conditions requiring the system to be reset (e.g. loss of connectivity) can break the
		// loop, and execution will be caught by the recovery loop and returned to the top.
		println!("Server startup complete.\nListening for subscription requests...");
		'processor:loop {
			sleep(Duration::new(0,1_000_000));
			inbin = [0;500];
			match listener.recv_from(&mut inbin) {
				Ok((nrecv,srcaddr)) => {
					// First make sure the sender is not banned.
					// It is important to do this as early as possible to minimize the impact of an
					// ongoing DoS attack. If we only used cryptographic validation on a per-packet
					// basis without the authentication ritual at the beginning of subscriptions,
					// then a large volume of garbage packets would cause a large amount of system
					// load due to the constant attempted decryption process.
					// Checking bans with a hash set scales very well and is a cheap operation to
					// perform at the beginning of the input-handling processes.
					if bannedips.contains(&srcaddr.ip()) {
						continue 'processor;
					} else if let Some(n) = banpoints.get(&srcaddr.ip()) {
					// If the sender is not already banned, next check if they are a known offender
					// who needs to be banned. This is a very slightly more costly operation than
					// checking bans, but is still pretty lightweight and can safely be done here.
					if *n > 10 {
						let _ = bannedips.insert(srcaddr.ip());
						let _ = reggs.remove(&srcaddr);
						continue 'processor;
					}
					} 
					// If we have no records on this sender, add an entry to the banpoints ledger
					// for them to keep track of their behavior.
					if !banpoints.contains_key(&srcaddr.ip()) {
						let _ = banpoints.insert(srcaddr.ip(),0);
					}
					// Packets containing a payload which is a single byte and one of the ASCII 
					// non-printing control characters are reserved for client-server functions. 
					// (Messages intended for clients with these characters should be longer than 
					// one byte.) Messages starting with 0x02 with a length of exactly 25 characters 
					// (an eight-byte auth-nonce encrypted and sent along with an eight-byte signature 
					// and an eight-byte nonce) are also considered server messages, but messages 
					// starting with 0x02 of any other length are passed to the client distribution
					// handler (although, since encrypted messages must be at least 24 bits long,
					// lengths of less than 24 will never validate).
					if (nrecv == 1 && inbin[0] <= 0x1F && inbin[0] != 0x02) || (nrecv == 25 && inbin[0] == 0x02) {
						match inbin[0] {
							0x18 => { // CANCEL
								// Subscription cancellation: The sender has notified us that they
								// are no longer listening and we should stop sending them
								// messages. This is technically an optional courtesy, since
								// eventually we'll just time them out, but it helps keep the
								// server load down if clients use this properly.
								// Whenever a subscription is cancelled for any reason, we send END
								// OF MEDIUM; the client can react to this however they like. 
								println!("Subscription canceled by {}",srcaddr);
								let _ = reggs.remove(&srcaddr);
								let _ = sendbytes(&listener,&srcaddr,&vec![0x19]); // END OF MEDIUM
							},
							0x16 => { // SYN
								// Subscription renewal: This is basically a dummy message that
								// clients can send to the server to have their subscription time
								// updated without having anything relayed to the others.
								if reggs.contains_key(&srcaddr) {
									let _ = reggs.insert(srcaddr,systime());
									let _ = sendbytes(&listener,&srcaddr,&vec![0x06]); // ACK
								} else {
									let _ = sendbytes(&listener,&srcaddr,&vec![0x15]); // NAK
								}
							},
							0x01 => { // START OF HEADING
								// Send the client an authentication nonce.
								println!("Auth request from {}. Sending authentication nonce...",srcaddr);
								let nonce:Vec<u8> = int2bytes(&rand::random::<u64>()).to_vec();
								let mut send:Vec<u8> = Vec::new();
								send.push(0x01);
								let mut sendcrypt:Vec<u8> = match encrypt(&nonce,&padpath) {
									Ok(data) => data,
									Err(why) => {
										println!("Error: Failed to encrypt nonce - {}",why.description());
										continue 'processor;
									},
								};
								let challengenonce:Vec<u8> = sendcrypt[sendcrypt.len()-8..sendcrypt.len()].to_vec();
								let _ = nonces.insert(srcaddr,(nonce,challengenonce.clone(),challengenonce));
								send.append(&mut sendcrypt);
								let _ = sendbytes(&listener,&srcaddr,&send);
							},
							0x02 => { // START OF TEXT
								if let Some((noncevalue,challengenonce,responsenonce)) = nonces.get_mut(&srcaddr) {
									if challengenonce == responsenonce {
										if inbin[17..25].to_vec() == *challengenonce {
											println!("Client {} returned invalid authentication. Access denied.",srcaddr);
											let _ = sendbytes(&listener,&srcaddr,&vec![0x19]); // END OF MEDIUM
											continue 'processor;
										}
										let recvdnonce:Vec<u8> = match decrypt(&inbin[1..25].to_vec(),&padpath) {
											Err(why) => {
												println!("Failed to decrypt returned nonce - {}",why.description());
												let _ = sendbytes(&listener,&srcaddr,&vec![0x19]); // END OF MEDIUM
												continue 'processor;
											},
											Ok(nonce) => nonce,
										};
										if recvdnonce == *noncevalue {
											println!("Client {} authenticated successfully; opening subscription.",srcaddr);
											let _ = sendbytes(&listener,&srcaddr,&vec![0x02]); // ACK
											let _ = reggs.insert(srcaddr,systime());
										} else {
											let _ = sendbytes(&listener,&srcaddr,&vec![0x19]); // END OF MEDIUM
											println!("Client {} returned invalid authentication. Access denied.",srcaddr);
											continue 'processor
										}
									}
								} else {
									// No nonce on file for this host? If we haven't sent this host 
									// a nonce, but they're trying to authenticate anyway, they must 
									// be either pulling something or glitching out. Either way,
									// that's a ban point.
									println!("Client {} tried to send authentication without being sent a nonce. Denying access.",srcaddr);
									let _ = sendbytes(&listener,&srcaddr,&vec![0x15]); // NAK
									if let Some(n) = banpoints.get_mut(&srcaddr.ip()) {
										*n += 1;
									}
									continue 'processor;
								}
							},
							0x06 => (), // ACK
							other => {
								// Unimplemented control code? NAK response for now.
								if let Some(t) = reggs.get_mut(&srcaddr) {
									*t = systime();
								}
								println!("Host {} sent unknown control packet {}",srcaddr,bytes2hex(&vec![other]));
								let _ = sendbytes(&listener,&srcaddr,&vec![0x15]); // NAK
							},
						}; // match inbin[0] ends here
						continue 'processor;
					}
					if !reggs.contains_key(&srcaddr) {
						// someone tried to send a message to other clients without first subscribing - this won't go.
						// note that we shouldn't do anything too drastic, because this could
						// easily be a legitimate client who just happened to miss the 0x19 packet
						// sent when their subscription timed out.
						let _ = sendbytes(&listener,&srcaddr,&vec![0x19]); // END OF MEDIUM
						if !banpoints.contains_key(&srcaddr.ip()) {
							let _ = banpoints.insert(srcaddr.ip(),0);
						}
						if let Some(n) = banpoints.get_mut(&srcaddr.ip()) {
							*n += 1;
						}
						continue 'processor;
					}
					if nrecv < 24 { 
						// 24 is the minimum size of valid encrypted packet: 0 message bytes, 
						// 8 timestamp bytes, 8 signature bytes, 8 nonce bytes. 
						// Messages of length less than this cannot be decrypted, so we can't
						// validate them, and won't relay them to clients.
						// This is not a bannable offense, because there's a chance it's due to
						// some type of send or receive error and not an evil client.
						let _ = sendbytes(&listener,&srcaddr,&vec![0x15]); // NAK
						continue 'processor;
					}
					// If we've come this far, it means the message is a valid payload for
					// decryption and comes from a subscribed and authenticated sender. It's time
					// to try decrypting it, so we can verify it for integrity and log its payload.
					let stampedmessage:Vec<u8> = match decrypt(&inbin[0..nrecv].to_vec(),&padpath) {
						Err(why) => match why.kind() {
							io::ErrorKind::InvalidData => {
								// Message decryption was attempted, but did not produce a valid
								// signed message. This is grounds for summary deauthentication.
								println!("Failed to verify packet received from {} - {}.",srcaddr,why.description());
								println!("Terminating subscription to {} due to verification failure.",srcaddr);
								let _ = sendbytes(&listener,&srcaddr,&vec![0x19]); // END OF MEDIUM
								let _ = reggs.remove(&srcaddr);
								continue 'processor;
							},
							_ => {
								// Message decryption failed for a reason that wasn't the sender's
								// fault (e.g. the pad file couldn't be read). This is not a
								// bannable or deauthenticable offense; instead, we simply notify
								// the sender that the server is having trouble.
								println!("Failed to decrypt packet received from {} - {}.",srcaddr,why.description());
								let _ = sendbytes(&listener,&srcaddr,&vec![0x1A]); // SUBSTITUTE (server-side error)
								continue 'processor;
							},
						},
						Ok(bytes) => bytes,
					};
					let message:Vec<u8> = stampedmessage[0..stampedmessage.len()-8].to_vec();
					println!("{} -> {} [{}]",srcaddr,String::from_utf8_lossy(&message),bytes2hex(&message));
					// Reaching this point means the message decrypted and validated successfully.
					// However, we still need to verify the timestamp to make sure this isn't a
					// replay attack.
					let mut timestamp:[u8;8] = [0;8];
					timestamp.copy_from_slice(&stampedmessage[stampedmessage.len()-8..stampedmessage.len()]);
					let inttimestamp:u64 = bytes2int(&timestamp);
					if inttimestamp > systime()+MAX_PACKET_DELAY {
						// Packet timestamp more than the allowed delay into the future? This is a
						// very weird and unlikely case, probably a clock sync error and not an
						// attack, but we'll reject it anyway just to be on the safe side.
						println!("Packet from {} supposedly had a timestamp {} ms in the future. Rejecting; please check your clocks.",
																										srcaddr,inttimestamp-systime());
						let _ = sendbytes(&listener,&srcaddr,&vec![0x15]); // NAK
						continue 'processor;
					} else if systime() > inttimestamp+MAX_PACKET_DELAY {
						// This is the most likely situation in an actual replay attack - the
						// timestamp is too far in the past. This means we need to reject the
						// packet, since it could be used to confuse clients maliciously.
						println!("Message from {} has a timestamp {} ms in the past, which is too long. Rejecting.",srcaddr,systime()-bytes2int(&timestamp));
						let _ = sendbytes(&listener,&srcaddr,&vec![0x15]); // NAK
						continue 'processor;
					}
					// By this point, the packet is fully verified and can be retransmitted. 
					let _ = reggs.insert(srcaddr,systime()); // update the activity timestamp for the sender
					let mut iterreggs:HashMap<SocketAddr,u64> = reggs.clone(); // clone the subscribed-clients table into a temporary table for iteration
					let _ = iterreggs.remove(&srcaddr); // remove the sender from the clone, to avoid returning to sender unnecessarily
					'iteractive:for knownaddr in iterreggs.iter() {
						if systime()-*knownaddr.1 > CONNECT_TIMEOUT {
							// Before sending the message to each client, check to make sure that
							// client isn't inactive. If it is inactive, knock it out of the table
							// of subscribers (the original one, not the clone we're iterating
							// over!). Also send off a notification of this event to the client in
							// question, just in case it really is still there and just had its
							// messages lost in transport.
							println!("Stopping transmission to {} due to inactivity.",knownaddr.0.ip());
							let _ = sendbytes(&listener,&knownaddr.0,&vec![0x19]); // END OF MEDIUM
							let _ = reggs.remove(&knownaddr.0);
							continue 'iteractive;
						}
						// If the client is not inactive, send the message to it, and automatically
						// repeat the transmission until 0x06 ACK is received in response, we've
						// tried ten times, or more than a second has passed with no response.
						match sendbytesuntil(&listener,&knownaddr.0,&inbin[..nrecv].to_vec(),&vec![0x06],&5000,&10) {
						//match sendbytes(&listener,&knownaddr.0,&inbin[..nrecv].to_vec()) {
							Err(why) => match why.kind() {
									io::ErrorKind::NotFound => {
										// No response after maximum number of attempts.
										// Subscription needs to be closed.
										let _ = sendbytes(&listener,&knownaddr.0,&vec![0x19]); // END OF MEDIUM
										let _ = reggs.remove(&knownaddr.0);
										println!("Terminating subscription for {} - No response.",knownaddr.0);
									},
									_ => {
										// Some other error, our fault. It's possible this is
										// transient, so we don't necessarily need to unsubscribe
										// the client.
										// It also wouldn't be especially useful to try to send
										// them a notification about this, because sending the
										// actual message didn't work.
										println!("Error while attempting to send to {} - {}.",knownaddr.0,why.description());
									},
							},
							Ok(_) => (), 
						};
					} // 'iteractive
					println!("Relayed message to {} clients.",reggs.len()-1); // looks dangerous, but we'd never have arrived here without at least one subscriber.
					let _ = sendbytes(&listener,&srcaddr,&vec![0x06]); // ACK
				}, // recv Ok
				Err(why) => match why.kind() {
					// Receiving from the UdpSocket failed for some reason. 
					io::ErrorKind::WouldBlock => (), // Nothing in the receive buffer; we'll come back later.
					io::ErrorKind::Interrupted => (), // Something stopped us in the middle of the operation, so I guess we'll try again later?
					_ => {
						// A real error happened, which is a problem. Maybe the OS nixed our socket
						// binding, or the network is borked? I dunno, but since this server is
						// supposed to run unsupervised, we'll just let the recovery loop catch us
						// and try to start again, rather than exiting. 
						println!("Error: Recv operation on socket failed - {}",why.description());
						break 'processor;
					},
				},
			}; // match recvfrom
			// Time delay for the processor is handled at the top, not here, so that `continue`
			// operations will still use the time delay.
		} // 'processor
		sleep(Duration::new(1,0));
	} // 'recovery
}
