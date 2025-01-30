# Network Tunnel File Transfer

## Overview
This project includes a program for sending and receiving network packets through IP-based tunneling. The project has two versions:
1. **GUI Version**: A graphical interface for selecting and sending files over the network.
2. **Console Version**: A command-line program for sending and receiving text packets.

## Table of Contents
- [Project Objective](#Project-Objective)
- [Project 1: GUI Application](#project-1-gui-application)
- [Project 2: Console Application](#project-2-console-application)
- [Installation and Setup](#installation-and-setup)
- [Usage](#usage)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## 1 Project Objective

The goal of this project is to send text files via tunneled network packets. The program utilizes the **Scapy** library to manage network packets and the IP protocol.

## 2 Project 1: GUI Application

The **graphical interface** version of this project features:
- File selection for transmission.
- Setting source and destination IP addresses.
- Sending data through tunneled packets.
- Displaying sent and received packets in a log window.

### 2.1 How to Run
To run the GUI version:
```sh
python "GUI Application.py"
```

### 2.2 Key Features
- **Graphical User Interface (GUI)** built with **Tkinter**.
- Checks **network connectivity** before sending data.
- Uses **Threads** for simultaneous sending and receiving.
- Supports **packet encapsulation and extraction**.

## 3 Project 2: Console Application

The **command-line** version of this project features:
- Sending data through **tunneled packets**.
- Receiving and reordering packets at the destination.
- Displaying received packet contents in the console.

### 3.1 How to Run
To run the console version:
```sh
python "Console Application.py"
```

### 3.2 Key Features
- Reads file lines and sends each line as an independent packet.
- Uses **IP flags** to manage packet ordering.
- Supports **Multithreading** for simultaneous sending and receiving.

## 4 Installation and Setup

1. **Install prerequisites**
   ```sh
   pip install scapy
   ```
2. **Run either the GUI or console version** (as described in the previous sections).

## 5 Usage
- In the **GUI version**:
  1. Select a file.
  2. Set source and destination IP addresses.
  3. Press the "Send File" button.
  4. Received packets will be displayed in the log window.

- In the **console version**:
  1. Place a file named `sample.txt` in the program directory.
  2. Run the program.
  3. Data will be sent to the destination and displayed.

## 6 Examples

**Example of sending via console:**
```sh
Sent (Number 1): Hello World
Sent (Number 2): This is a test
...
All packets received:
Received (number of 1): Hello World
Received (number of 2): This is a test
```

**Example of sending via GUI:**
A window opens displaying information about sent and received packets.

## 7 Contributing
Contributions are welcome! To contribute:
1. **Fork** the repository.
2. Create a **new branch** for your changes.
3. Submit a **Pull Request**.

## 8 License
This project is released under the **MIT License**.

## 9 Authors
This project was developed by **[Ali Bokaei](https://github.com/AliBokaei)** and **[Amina Shojaei](https://github.com/aminashojaei)**.

