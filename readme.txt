README - encoderEmulator.py and runMultipleEncoders.py

This program takes details about the IP:port wanting to run the encoder on, will receive SCTE104 messages and respond accordingly. 
Also has a working clock that can be used from either a loop of a certain length, or with real time.

runMultipleEncoders.py is a way of running multiple encoders in the same Powershell window, outputted data will be prefaced with the IP and port the specific encoder is using. Inside the code is an array where the commands can be edited to run as many encoders as needed. 


HOW TO RUN

Run encoderEmulator.py from command line for LOOPING stream:
python encoderEmulator.py [param1] [param2] [param3] [param4]
[param1] - (String) ip address for the encoder
[param2] - (Integer) port number for the encoder
[param3] - (String) stream start time as a time code HH:MM:SS:FF
[param4] - (String) stream end time as a time code HH:MM:SS:FF

Run encoderEmulator.py from command line for REAL TIME stream:
python encoderEmulator.py [param1] [param2] [param3]
[param1] - (String) ip address for the encoder
[param2] - (Integer) port number for the encoder
[param3] - (String) real time indicator ('realTime')

Run runMultipleEncoders.py from command line
python runMultipleEncoders.py


