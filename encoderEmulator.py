import socket
import sys
import datetime
import threading
import time
import warnings

# Ignore specific deprecation warning by category
warnings.filterwarnings("ignore", category=DeprecationWarning)


#Global value for message number
messageNumber = 0

#global value for computerStartTime
computerStartTime = 0

#global value for port number to display alongside messages
portNumber = 0

#global value for the IP address to display alongside messages
ipAddress = 0


def connectTCP(ip, port, streamStartTime, streamEndTime):
    """
    Function to connect to the TCP port of the encoder
    Parameters:
    ip(String): The IP address of the encoder
    port(int): The port of the encoder
    streamStartTime(String): The start time of the stream
    streamEndTime(String): The end time of the string
    Returns:
    encoderSocket (Socket): The socket
    """
    """
    #Create the TCP socket
    encoderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    
    
    # Get the current time
    timestamp_string = getTimestampString()
    

    
    #Connect to the socket
        
    try:
        encoderSocket.connect((ip, port))
        print(f"[{timestamp_string}] Connected to {ip}:{port}")


    except ConnectionRefusedError:
        print(f"[{timestamp_string}] Connection was refused. Ensure the server is running or check the IP and port.")
    except Exception as e:
        print(f"An error occurred: {e}")

    # Return the socket
    return encoderSocket
    
    
    """
    #assign port number
    global portNumber
    portNumber = port
    #assign IP
    global ipAddress
    ipAddress = ip
    
    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_socket.bind((ip, port))

    # Listen for incoming connections (max queued connections)
    server_socket.listen(5)

    print(f"\n[{ipAddress}:{portNumber}] Server is listening on {ip}:{port}")
    # Accept incoming connection
    client_socket, client_address = server_socket.accept()
    print(f"[{ipAddress}:{portNumber}] Connected to {client_address}")
    while True:
        

        # Receive data from client
        data = client_socket.recv(1024)
        hex_string = ''.join([hex(byte)[2:].zfill(2) for byte in data])
        if not data:
            break
        
        # Call functions based on the received message content
        if hex_string.startswith("0001"):
            # Call function for init request
            print(f"\n[{ipAddress}:{portNumber}] INIT REQUEST RECEIVED: {hex_string}")
            processInitRequest(client_socket, hex_string)
         
        elif hex_string.startswith("0003"):
            # Call function for alive request
            print(f"\n[{ipAddress}:{portNumber}] ALIVE REQUEST RECEIVED: {hex_string}")
            processAliveRequest(client_socket, hex_string, streamStartTime, streamEndTime)
            
 
        elif hex_string[32:36] == "0101":
            # Call function for splice request
            print(f"\n[{ipAddress}:{portNumber}] SPLICE REQUEST RECEIVED: {hex_string}")
            processSpliceRequest(client_socket, hex_string, streamStartTime, streamEndTime)
            

    # Close the client socket
    client_socket.close()
    # Close the server socket
    server_socket.close()
    
    
def incrementMessageNumber():
    """
    Function to increment message number
    Parameters: 
    None
    Returns:
    None
    """
    global messageNumber
    if (messageNumber < 255):
        messageNumber += 1
    else:
        messageNumber = 0
        

def getTimestampString():
    """
    Function to get the timestamp string
    Parameters: 
    None
    Returns
    timeStampString(String)
    """
    # Get the current time
    current_time = datetime.datetime.now().time()

    # Format the time as HH:MM:SS string
    timeStampString = current_time.strftime('%H:%M:%S')
    return(timeStampString)
    

def processAliveRequest(socket, message, streamStartTime, streamEndTime):
    """
    Function to process an alive request
    Parameters:
    socket(socket): The socket to send data on
    message(String): The received message
    streamStartTime(String): The start time of the stream
    streamEndTime(String): The end time of the string
    Returns:
    None
    """
    #Return an alive response message
    
    #First 2 bytes is the OP ID, in this case 0x0004
    opID = "0004"
    #Message size always 21 as 13 + 8 bytes data
    messageSize = hex(21)[2:].zfill(4)
    #Result is result code, correct
    resultCode = hex(100)[2:].zfill(4)
    #Result extension always FFFF
    resultExt = "FFFF"
    #protocol version always "00"
    protocol = "00"
    #message number is the current global message number
    global messageNumber
    messageNo = hex(messageNumber)[2:].zfill(2)
    #DPI Pid Index is the current DPI pid index from the message.
    dpiPID = message[22:26]
    #Data is TIME, since Jan 6 1980
    currentStreamTime = getCurrentTime(streamStartTime, streamEndTime)
    #get that time in ms
    #calculate how many ms in stream time
    splitTime = currentStreamTime.split(":")
    timeHours = int(splitTime[0])
    timeMins = int(splitTime[1])
    timeSecs = int(splitTime[2])
    timeFrames = int(splitTime[3])
    currentStreamTimeMS = int(timeHours*60*60*1000 + timeMins*60*1000 + timeSecs*1000 + (timeFrames/25)*1000)
    
    #seconds from jan6 1980 to midnight just been 
    # Get the current date in YYYY/MM/DD format
    current_date = datetime.datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d')
    # Get the current timestamp in seconds since epoch
    current_timestamp = time.time()
    # Get the timestamp at midnight on the current day
    midnight_timestamp = datetime.datetime.strptime(current_date, '%Y-%m-%d').replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    # Calculate the time at midnight on the current day in milliseconds since January 6, 1980
    jan_6_1980_timestamp = datetime.datetime(1980, 1, 6).timestamp()
    milliseconds_since_1980 = (midnight_timestamp - jan_6_1980_timestamp) * 1000
    
    #Get full MS past 1980
    millisecondsFull = milliseconds_since_1980+currentStreamTimeMS
    #split this into seconds and milliseconds
    seconds = int(millisecondsFull // 1000)
    microseconds = int((millisecondsFull % 1000)*1000)
    #convert to 4 byte hexes
    secondsHex = hex(seconds)[2:].zfill(8)
    microsecondsHex = hex(microseconds)[2:].zfill(8)
    
    #Put all together in a message
    messageToSend = f"{opID}{messageSize}{resultCode}{resultExt}{protocol}{messageNo}{dpiPID}{secondsHex}{microsecondsHex}"
    global portNumber
    print(f"[{ipAddress}:{portNumber}] Sending ALIVE RESPONSE message: {messageToSend}")
    sendMessageTCP(socket, messageToSend)
    
def processInitRequest(socket, message):
    """
    Function to process an init request
    Parameters:
    socket(socket): The socket to send data on
    message(String): The received message
    Returns:
    None
    """
    #Return an init response message on the socket
    
    #First 2 bytes is the OP ID, in this case 0x0002
    opID = "0002"
    #Message size always 13 as no data
    messageSize = hex(13)[2:].zfill(4)
    #Result is result code, correct
    resultCode = hex(100)[2:].zfill(4)
    #Result extension always FFFF
    resultExt = "FFFF"
    #protocol version always "00"
    protocol = "00"
    #message number is the current global message number
    global messageNumber
    messageNo = hex(messageNumber)[2:].zfill(2)
    #DPI Pid Index is the current DPI pid index from the message.
    dpiPID = message[22:26]
    #No DATA
    #Put all together in a message
    messageToSend = f"{opID}{messageSize}{resultCode}{resultExt}{protocol}{messageNo}{dpiPID}"
    global portNumber
    print(f"[{ipAddress}:{portNumber}] Sending INIT RESPONSE message: {messageToSend}")
    sendMessageTCP(socket, messageToSend)
    
    
    
def processSpliceRequest(socket, message, streamStartTime, streamEndTime):
    """
    Function to process a splice request
    Parameters:
    socket(socket): The socket to send data on
    message(String): The received message
    streamStartTime(String): The start time of the stream
    streamEndTime(String): The end time of the string
    Returns
    None
    """
    #get times to see if viable splice
    #time from message
    spliceHours = int(message[22:24],16)
    spliceMins = int(message[24:26],16)
    spliceSecs = int(message[26:28],16)
    spliceFrames = int(message[28:30],16)
    #convert to ms
    spliceTimeMS = int(spliceHours*60*60*1000 + spliceMins*60*1000 + spliceSecs*1000 + (spliceFrames/25)*1000)
    
    #get current time
    currentStreamTime = getCurrentTime(streamStartTime, streamEndTime)
    #convert to ms
    #calculate how many ms in stream time
    splitTime = currentStreamTime.split(":")
    timeHours = int(splitTime[0])
    timeMins = int(splitTime[1])
    timeSecs = int(splitTime[2])
    timeFrames = int(splitTime[3])
    currentStreamTimeMS = int(timeHours*60*60*1000 + timeMins*60*1000 + timeSecs*1000 + (timeFrames/25)*1000)
    #assign viability
    if spliceTimeMS < currentStreamTimeMS:
        viable = False
    else:
        viable = True
    
    
    #first send an inject response
    #First 2 bytes is the OP ID, in this case 0x0007
    opID = "0007"
    #Message size always 14 as 1 byte of data
    messageSize = hex(14)[2:].zfill(4)
    #Result is result code, dependent on if viable
    if viable:
        resultCode = hex(100)[2:].zfill(4)
    else:
        resultCode = hex(121)[2:].zfill(4)
    #Result extension always FFFF
    resultExt = "FFFF"
    #protocol version always "00"
    protocol = "00"
    #message number is the current global message number
    global messageNumber
    messageNo = hex(messageNumber)[2:].zfill(2)
    #DPI Pid Index is the current DPI pid index from the message.
    dpiPID = message[22:26]
    #Data is the messageNumber of the received message, 1 byte
    messageNoInit = message[12:14]
    #Put all together in a message
    messageToSend = f"{opID}{messageSize}{resultCode}{resultExt}{protocol}{messageNo}{dpiPID}{messageNoInit}"
    global portNumber
    print(f"[{ipAddress}:{portNumber}] Sending SPLICE REQUEST RESPONSE message: {messageToSend}")
    sendMessageTCP(socket, messageToSend)
    
    
    #now wait for the time when the message needed to be sent and send back an inject complete response only if viable
    if resultCode == hex(100)[2:].zfill(4):
        #calculate time until splice insert
        timeToSplice = spliceTimeMS - currentStreamTimeMS
        #wait for that time
        time.sleep(timeToSplice/1000)
        #Send splice inject complete message
        
        #First 2 bytes is the OP ID, in this case 0x0008
        opID = "0008"
        #Message size always 15 as 2 byte of data
        messageSize = hex(14)[2:].zfill(4)
        #Result is result code, dependent on if viable
        if viable:
            resultCode = hex(100)[2:].zfill(4)
        else:
            resultCode = hex(121)[2:].zfill(4)
        #Result extension always FFFF
        resultExt = "FFFF"
        #protocol version always "00"
        protocol = "00"
        #message number is the current global message number
        messageNo = hex(messageNumber+1)[2:].zfill(2)
        #DPI Pid Index is the current DPI pid index from the message.
        dpiPID = message[22:26]
        #Data is the messageNumber of the received message, 1 byte
        messageNoInit = message[12:14]
        #Data is also the cue message number, i.e., the number of splice requests queued, for purpose this will always be 1. 1 byte
        cueNumber = hex(1)[2:].zfill(2)
        
        #Put all together in a message
        messageToSend = f"{opID}{messageSize}{resultCode}{resultExt}{protocol}{messageNo}{dpiPID}{messageNoInit}{cueNumber}"
        print(f"[{ipAddress}:{portNumber}] Sending INJECT COMPLETE RESPONSE message: {messageToSend}")
        sendMessageTCP(socket, messageToSend)
    
    
    
    
    
    
def sendMessageTCP(socket, message):
    """
    A function to send a message on a given socket
    Parameters:
    socket (Socket): The socket to send on
    messasge (String) The message to send
    Returns:
    code(int): The return code
    """
    #Get hex from message
    binaryData = bytes.fromhex(message)
    #Send message
    socket.send(binaryData)
    incrementMessageNumber()
    
    
def listenToSocket(socket):
    """
    A function to listen on the given socket and react accordingly
    Parameters:
    socket (Socket): The socket to send on
    Returns:
    code(int): The return code
    """
    while True:
        try:
            # Receive data from the socket
            data = socket.recv(1024)
            hex_string = ''.join([hex(byte)[2:].zfill(2) for byte in data])
            if not data:
                break
            
            # Call functions based on the received message content
            if data.startswith("0001"):
                # Call function for init request
                processInitRequest(socket, hex_string)
             
            elif data.startswith("0003"):
                # Call function for alive request
                processAliveRequest(socket, hex_string)
     
            elif data.startswith("0101"):
                # Call function for splice request
                processSpliceRequest(socket, hex_string)
                
    
            

        except Exception as e:
            print(f"An error occurred: {e}")
            break

    # Close the socket when done
    socket.close()


def getCurrentTime(streamStartTime, streamEndTime):
    """
    Function to return the current time on a thread
    Parameters:
    streamStartTime(String): The start time of the streamEndTime
    streamEndTime(String): The end time of the streamEndTime
    Returns:
    timeOut(String): The current time
    """
    
    #get current time in ms
    current_time = time.time()  # Get current time in seconds since epoch
    currentTime = int((current_time % 86400) * 1000)  # Calculate milliseconds since midnight
    #get how many MS of the stream have gone
    global computerStartTime
    streamTimeBeen = currentTime - computerStartTime
    #if the stream time has an end, calculate if loops
    if not(streamEndTime == 'x'):
        #calculate how many ms in stream time
        splitStreamStart = streamStartTime.split(":")
        streamStartHours = int(splitStreamStart[0])
        streamStartMins = int(splitStreamStart[1])
        streamStartSecs = int(splitStreamStart[2])
        streamStartFrames = int(splitStreamStart[3])
        streamStartMS = int(streamStartHours*60*60*1000 + streamStartMins*60*1000 + streamStartSecs*1000 + (streamStartFrames/25)*1000)
        
        splitStreamEnd = streamEndTime.split(":")
        streamEndHours = int(splitStreamEnd[0])
        streamEndMins = int(splitStreamEnd[1])
        streamEndSecs = int(splitStreamEnd[2])
        streamEndFrames = int(splitStreamEnd[3])
        streamEndMS = int(streamEndHours*60*60*1000 + streamEndMins*60*1000 + streamEndSecs*1000 + (streamEndFrames/25)*1000)
        streamTimeMS = streamEndMS - streamStartMS
        
        
        #get the remainder of how many loops have been
        remainder = streamTimeBeen%streamTimeMS
        #get how many loops have been
        loops = streamTimeBeen//streamTimeMS
        #print(f"Stream length {streamTimeMS}, Stream Time {streamTimeBeen}, Remainder {remainder}, Loops {loops}")
        
        #convert this to a time and return
        
        total_seconds = remainder // 1000
        milliseconds = remainder % 1000

        # Calculate hours, minutes, and seconds
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        frames = int((milliseconds/1000)*25)
        
        hoursString = str(hours).zfill(2)
        minsString = str(minutes).zfill(2)
        secsString = str(seconds).zfill(2)
        framesString = str(frames).zfill(2)
        
        timeOut = (f"{hoursString}:{minsString}:{secsString}:{framesString}")
        return(timeOut)
    else:
        #if using real time, return real time
        current_time = datetime.datetime.now().time()
        milliseconds = current_time.microsecond // 1000  # Get milliseconds

        # Calculate the value as per the frames
        converted_value = int((milliseconds / 1000) * 25)

        # Format the time to HH:MM:SS:FF
        timeOut = current_time.strftime('%H:%M:%S') + f":{converted_value:02d}"
        return(timeOut)
        
   
    
    

if __name__ == "__main__":
    #get data about what to listen on from args
    ip = sys.argv[1]
    port = int(sys.argv[2])
    #get data about loop from args
    #if using a looping time
    if len(sys.argv) > 4:
        streamStartTime = sys.argv[3]
        streamEndTime = sys.argv[4]

        #get stream start time
        current_time = time.time()  # Get current time in seconds since epoch
        computerStartTime = int((current_time % 86400) * 1000)  # Calculate milliseconds since midnight

        connectTCP(ip, port, streamStartTime, streamEndTime)
        #listenToSocket(socket)
    else:
        #if using real time
        current_time = datetime.datetime.now().time()
        milliseconds = current_time.microsecond // 1000  # Get milliseconds

        # Calculate the value as per the frames
        converted_value = int((milliseconds / 1000) * 25)

        # Format the time to HH:MM:SS:FF
        streamStartTime = current_time.strftime('%H:%M:%S') + f":{converted_value:02d}"
        
        current_time = time.time()  # Get current time in seconds since epoch
        computerStartTime = int((current_time % 86400) * 1000)  # Calculate milliseconds since midnight
        
        #run connectTCP with no stream end time as real time no loops
        connectTCP(ip, port, streamStartTime, 'x')
        
    
    
    




