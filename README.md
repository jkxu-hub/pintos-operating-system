# Description
A single threaded operating system framework for the 80x86 architecture. This project was done with a team of college classmates. The base code was written by Ben Pfaff, supporting only basic operating systems tasks like FIFO thread scheduling, boot support, and basic peripheral support. 

# Features Added
* A priority queue thread scheduler to prevent thread starvation, improve CPU throughput, and enable efficient thread switching.
* A syscall handler that allows user programs to invoke kernel system calls.
* Virtual Memory support: an on demand paging system which enables segments of large programs to be swapped between ram and disk.

# Running Pintos

### Simulators
Pintos is run on a system simulator that simulates the 80x86 CPU and its peripheral devices. The Simulator used is Bochs. Bochs is then simulated within a docker container running Ubuntu.
So in order to run Pintos, we will need to run Ubuntu, then run Bochs, and only then can we run Pintos. 

Theoretically, Pintos can run on a bare metal PC, however this approach is more portable.

## To setup the Ubuntu environment use docker:
* Ensure Docker is installed on your PC.
* Execute these commands in the root directory of the cloned repo 
```
docker build -t pintos .
docker run --name=pintos_cont -td pintos
docker exec -it pintos_cont bash
```
A bash terminal running ubuntu should appear

## To build and run Pintos
In the bash terminal execute these commands:

Building Pintos:
```
cd ~/../home/pintos/src/threads
make
```
Running pintos:
```
cd ~/../home/pintos/src/threads/build
pintos run alarm-multiple
```

Testing Pintos:
```
cd ~/../home/pintos/src/threads/build
make check
```

## Credits:
* Dockerfile and makefile were written by Farshad Ghanei
* Project code was written by Jeffrey Xu, Jude Chahine, and Heba Mahran.

## Disclaimer
* Please do not use this code to cheat on assignments.
