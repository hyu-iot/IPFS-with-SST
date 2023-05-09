# IPFS-with-SST
The project for IPFS applying to SST

- Environment Setting
  - Install the Raspberry Pi 4 in other places such as Seoul and US. 

- File -> encrypted file using AES-CBC algorithm -> Make one file including IV, Provider infomation, crypto spec, and encrypted value -> ipfs add the file -> get a hash value

- There are two senenarios to get the file
  - When you want to download it right away -> send the hash value to secure connection right away.
  - When you want to download it later -> You just have to download the hash value yourself later. (Make Table)
  
- Start the command in main Raspberry Pi4
  - gcc secure_encrypt.c -o se.o -lcrypto -lssl
  - ./se.o

- Other Raspberry Pi4 code
  - gcc rpi_experiment.c -o re.o -lcrypto -lssl
  - ./re.o
