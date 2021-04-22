/*
*   IPK project2: [ZETA] Sniffer
*   Author: Yehor Pohrebniak
*   Login: xpohre00
*/

/*
*   Libraries
*/
#include <iostream>
#include <string>
#include <bits/stdc++.h>

/*
* Errors
*/
#define INVALIDARGUMENTS 10;

/*
*   Struct for date from arguments
*/
struct arguments {
    bool interfaceFlag = false;
    bool portFlag = false;
    bool tcp = false;
    bool udp = false;
    bool arp = false;
    bool icmp = false;
    bool n = false;
    bool invalidArguments = false;

    int packetCount = 1;
    std::string interface = ""; //Default mus be empty
    std::string port;
    
};

/*
* Function to check if string is a number
*/
bool isNum(std::string str) {
    for (char c: str) {
        if (!std::isdigit(c)) {
            return false;
        }
    }
    return true;
}

/*
*   Function for argument parsing
*/
struct arguments argparse(int argc, char *argv[]) {
    struct arguments arg;
    std::string argument;

    //vector for argument controls in argumnet is -i or --interface
    std::vector<std::string> argNames{"-n", "--udp", "-u", "--tcp", "-t", "--arp", "--icmp", "-p"};
    std::vector<std::string> argNamesI{"-i", "--interface"};

    for (int i = 1; i < argc; i++) { 
        argument = argv[i];
   
        if (argument == "--udp" || argument == "-u") {
            if (arg.udp) {      //More then 1 --udp or -u
                arg.invalidArguments = true;
                return arg;
            }
            
            arg.udp = true;

        } else if (argument == "--tcp" || argument == "-t") {
            if (arg.tcp) {      //More then 1 --tcp or -t
                arg.invalidArguments = true;
                return arg;
            }
            
            arg.tcp = true;

        } else if (argument == "-i" || argument == "--interface") {
            if (arg.interfaceFlag) {        //More then 1 --interface or -i
                arg.invalidArguments = true;
                return arg;
            }

            i++;
            if (i >= argc) {
                arg.interfaceFlag = true;
                continue;
            }

            std::string nextArgument = argv[i];

            if(std::find(argNames.begin(), argNames.end(), nextArgument) != argNames.end()) {
                /* -i without a parametr */
                arg.interfaceFlag = true;
            } else if (std::find(argNamesI.begin(), argNamesI.end(), nextArgument) != argNamesI.end()) {
                /* -i with parament --interface or -i*/
                arg.invalidArguments = true;
                return arg;
            } else {
                /* -i with a parametr */
                arg.interfaceFlag = true;
                arg.interface = nextArgument;
            }

        } else if (argument == "--arp") {
            if (arg.arp) {      //More then 1 --arp
                arg.invalidArguments = true;
                return arg;
            }

            arg.arp = true;

        } else if (argument == "--icmp") {
            if (arg.icmp) {      //More then 1 --icmp
                arg.invalidArguments = true;
                return arg;
            }

            arg.icmp = true;

        } else if (argument == "-n") {
            i++;
            if (arg.n || i >= argc) {      //More then 1 --icmp
                arg.invalidArguments = true;
                return arg;
            }
            
            std::string number = argv[i];

            if (!isNum(number)) {
                arg.invalidArguments = true;
                return arg;
            }

            arg.packetCount = std::stoi(number);
            arg.n = true;

        } else if (argument == "-p") {
            i++;
            if (arg.n || i >= argc) {      //More then 1 --icmp
                arg.invalidArguments = true;
                return arg;
            }
            
            arg.port = argv[i];
            arg.portFlag = true;

        } else {
            arg.invalidArguments = true;
            return arg;
        }
    }

    return arg;
}

/*
*   Main program
*/
int main(int argc, char *argv[]) {
    struct arguments arg = argparse(argc, argv);

    //Checks if agruments was correct
    if (arg.invalidArguments) {
        return INVALIDARGUMENTS;
    }
    std::cout << "Argument ok" << std::endl;

    
    return 0;
}