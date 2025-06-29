# dns-sniffer

<!-- ABOUT THE PROJECT -->
## About The DNS sniffer

This small program deal sniff response DNS packets.

<!-- GETTING STARTED -->
## Getting Started

The packt sniffer uses libpcap, and there for uses EBF in order to receive only response packets.
The test ware made on linux machine (ubunru server 24.04 TLS)

### Prerequisites

The code uses the libpcap development package, install if not already installed
* libpcap
  ```sh
  sudo apt-get install libpcap-dev
  ```

### Compile and run instructions 

In order to run the program follow the steps 

1. Clone the repo
   ```sh
   git clone https://github.com/yaronO/dns-sniffer.git
   ```
2. cd to directory
   ```sh
   cd dns-sniffer
   ```
3. compile 
   ```sh
   gcc -o dns-sniffer dns-sniffer.c -lpcap
   ```
4. run`
   ```
   sudo ./dns-sniffer
   ```
