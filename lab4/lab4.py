#!/usr/bin/env python3

import dns.message
import dns.resolver
import socket
import sys
import os

def createDNSHeader(ID):
    # create 12 byte header
    header = bytearray(12)
    
    # Set ID number
    ID = ID.to_bytes(2, 'big')
    
    # set flags
    QR = 0
    OPCODE = 0
    AA = 0
    RC = 0
    RD = 1
    RA = 0
    Z = 0
    RCODE = 0
    flags = (( QR << 15 ) | ( OPCODE << 14 ) | ( AA << 10 ) | ( RC << 9 ) | ( RD << 8 ) | ( RA << 7 ) | ( Z << 4 ) | RCODE ).to_bytes(2,'big')
    
    # set QDCOUNT
    QDCOUNT = 1
    QDCOUNT = QDCOUNT.to_bytes(2, 'big')
    
    # set ANCOUNT
    ANCOUNT = 0
    ANCOUNT = ANCOUNT.to_bytes(2, 'big')
    
    # set NSCOUNT
    NSCOUNT = 0
    NSCOUNT = NSCOUNT.to_bytes(2, 'big')
    
    # set ARCOUNT
    ARCOUNT = 0
    ARCOUNT = ARCOUNT.to_bytes(2, 'big')
    
    # combine header
    header = ID + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    
    return header

def createDNSQuestion(domain, type):
    # create question
    question = bytearray()
    
    # split domain into labels
    labels = domain.split('.')
    
    # add each label to question
    for label in labels:
        question += len(label).to_bytes(1, 'big')
        question += label.encode()
    
    # add null byte to end of question
    question += b'\x00'
    
    # set QTYPE
    if type == "A":
        QTYPE = 1
    elif type == "CNAME":
        QTYPE = 5
    else:
        return "Error: Invalid record type"
    QTYPE = QTYPE.to_bytes(2, 'big')
    
    # set QCLASS
    QCLASS = 1
    QCLASS = QCLASS.to_bytes(2, 'big')
    
    # combine question
    question += QTYPE + QCLASS
    
    return question

def createDNSQuery(ID, domain, type):
    # create header
    header = createDNSHeader(ID)
    
    # create question
    question = createDNSQuestion(domain, type)
    
    return header + question

def decode_name(data, offset):
    """
    Decodes a domain name starting at the given offset in the data buffer,
    handling DNS name compression (pointers). Returns a tuple (name, next_offset),
    where 'name' is the decompressed domain name (as a string) and 'next_offset' is
    the position in data immediately after the name (unless a pointer was used).
    """
    labels = []
    original_offset = offset
    jumped = False

    while True:
        length = data[offset]
        # Check if this is a pointer (first two bits are 1)
        if (length & 0xC0) == 0xC0:
            # Pointer: combine current byte and the next one to get offset.
            if offset + 1 >= len(data):
                break  # safety check
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2  # Only update once if we haven't jumped yet
            offset = pointer
            jumped = True
        else:
            # If length is zero, we've reached the end of the name.
            if length == 0:
                offset += 1
                if not jumped:
                    original_offset = offset
                break
            offset += 1
            label = data[offset:offset+length]
            labels.append(label.decode('utf-8', errors='replace'))
            offset += length

    return '.'.join(labels), original_offset

def parseDNSResponse(query, response):
    # Start parsing after the query (header+question)
    offset = len(query)
    
    # Decode the NAME field from the answer using our decompression function.
    name, offset = decode_name(response, offset)
    
    # Get TYPE (2 bytes)
    TYPE = int.from_bytes(response[offset:offset+2], 'big')
    offset += 2
    # Get CLASS (2 bytes)
    CLASS = int.from_bytes(response[offset:offset+2], 'big')
    offset += 2
    # Get TTL (4 bytes)
    TTL = int.from_bytes(response[offset:offset+4], 'big')
    offset += 4
    # Get RDLENGTH (2 bytes)
    RDLENGTH = int.from_bytes(response[offset:offset+2], 'big')
    offset += 2
    # Get RDATA (RDLENGTH bytes)
    RDATA = response[offset:offset+RDLENGTH]
    
    # If the record type is CNAME, RDATA is a compressed domain name.
    if TYPE == 5:
        cname, _ = decode_name(response, offset)
        # Return the decompressed CNAME as bytes (or as string if you prefer)
        return cname.encode()
    elif TYPE == 1:  # A record
        return RDATA
    else:
        return b""
    
def dnsQuery(ID, domain, type):
    
    # create DNS query
    dnsQuery = createDNSQuery(ID, domain, type)

    # Create a UDP socket and set a timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10.0)

    # Get the IP of a DNS server from the default resolver
    dnsIP = dns.resolver.Resolver().nameservers[0]
    dnsPort = 53
    
    # Send the DNS query to the DNS server over UDP
    sock.sendto(dnsQuery, (dnsIP, dnsPort))

    # Wait for and receive the response from the DNS server
    try:
        # Wait for and receive the response from the DNS server
        response, addr = sock.recvfrom(4096)
    except Exception as e:
        response = None
        
    # process the response
    if response:
        response = parseDNSResponse(dnsQuery, response)
        
    return response
        
    
def printResponseIP(response):
    if response:
        print('.'.join(str(byte) for byte in response))
    else:
        print("Error: No response received")
        
def writeHostname(username, sequence_number, chunk):
    """
    Create a hostname in the form:
    w.<username>.<sequence_number>.<chunk_data>.lab4.ece568.ca
    
    The chunk data is hex-encoded.
    """
    # Hex-encode the chunk. If chunk is a string, we encode it to bytes first.
    hex_chunk = chunk.encode('utf-8').hex()
    # Create the hostname string
    hostname = f"w.{username}.{sequence_number}.{hex_chunk}.lab4.ece568.ca"
    return hostname

def readHostname(username, sequence):
    """
    Create a hostname in the form:
    r.<username>.<sequence_number>.lab4.ece568.ca
    """
    hostname = f"r.{username}.{sequence}.lab4.ece568.ca"
    return hostname

def parseDataMsg(msg):
    """
    Parse a data message in the form:
      d.<hexdata>.lab4.ece568.ca
    or nodata.lab4.ece568.ca if there is no data.
    Returns the decoded message as a string.
    """
    if msg:
        # Assume msg is a bytes object representing the decompressed hostname.
        # Split the message by the '.' character.
        msg_parts = msg.split(b'.')
        # Check if the message is a data message (starts with b'd').
        if msg_parts[0] == b'd' and len(msg_parts) >= 2:
            # Get the hex-encoded data part.
            hex_data = msg_parts[1].decode('utf-8')
            try:
                # Convert the hex data back to bytes and then decode to a string.
                return bytes.fromhex(hex_data).decode('utf-8')
            except Exception as e:
                print("Error decoding hex:", e)
                return hex_data  # Fallback: return the hex string.
        else:
            return -1  # Indicates no data message.
    else:
        return None
        
if __name__ == "__main__":
    mailboxName = os.getlogin()
    
    if len(sys.argv) == 2:
        # Write mode: break the message into chunks and send each chunk
        msg = sys.argv[1]
        msg_bytes = msg.encode('utf-8')
        chunks = [msg_bytes[i:i+30] for i in range(0, len(msg_bytes), 30)]
        
        for i, chunk in enumerate(chunks, 1):
            # Create hostname of the form: w.adamtaback.<sequence>.<chunk_data>.lab4.ece568.ca
            hostname = writeHostname(mailboxName, i, chunk.decode())
            try:
                response = dnsQuery(i, hostname, "A")
                printResponseIP(response)
            except Exception as e:
                print("Error in DNS query:", e)
                sys.exit(2)
    else:
        # Read mode: repeatedly query for stored messages.
        seq = 1
        full_message = ""
        while True:
            hostname = readHostname(mailboxName, seq)
            try:
                response = dnsQuery(seq, hostname, "CNAME")
            except Exception as e:
                print("Error in DNS query:", e)
                sys.exit(2)
                
            parsed_msg = parseDataMsg(response)
            if parsed_msg == -1:  # Indicates no more data (e.g., "nodata.lab4.ece568.ca")
                break
            elif parsed_msg is None:
                print("Error: No data received")
                sys.exit(1)
            else:
                full_message += parsed_msg
            seq += 1

        if full_message == "":
            # No data was accumulated; exit with status 1.
            sys.exit(1)
        else:
            print(full_message)
            sys.exit(0)
        
    sys.exit(0)          