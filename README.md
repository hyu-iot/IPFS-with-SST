# IPFS-with-SST
The project for IPFS applying to SST

- SST(Secure Swarm Toolkit)
  - Provide the access authorization through the secure handshakes
  - https://github.com/iotauth/iotauth 

- Environment Setting
  - Install the Raspberry Pi 4 in other places such as Seoul and US. 

- According to connecting with Auth, two entities have the secure key.
- File -> encrypted file using AES-CBC algorithm -> Make one file including IV, Provider infomation, crypto spec, and encrypted value -> ipfs add the file -> get a hash value

- There are three entities which are entity client, entity server, and data management entity
- Entity Client
  - entity client gets the session key from Auth
  - entity client can communicate with entity server using session key
  - entity client uploads the file and transfer the data to  

- Entity Server
  - entity server gets the session key from Auth
  - entity server can communicate with entity client using session key
  - entity server request the file info and downloads the file.

- Data Management Entity
  - data management entity provides the sessionkey id, IV, hash value after confirming the entity's name.
  
- We'll make the FileSharingTable(FST) to SST
  - FST can be only accessed by the Auth
  - FST can provide the filesharing information comparing with owner and downloader

- Implementation(first scenario)
    - https://github.com/iotauth/sst-c-api/tree/e27ee4c68a2902fdc1b019bbf35785b7aea9073c
    - $cd $SST_ROOT/entity/sst-c-api/examples $mkdir build && cd build $cmake ../ $make
    - 

- Start the command in main Raspberry Pi4
  - ipfs daemon in another terminal
  - ./entity_client ../c_client.config

- Other Raspberry Pi4 code
  - ipfs daemon in another terminal
  - ./entity_server ../c_server.config
