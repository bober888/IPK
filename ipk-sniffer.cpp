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
#include <pcap/pcap.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>        //Provides declarations for udp header
#include <netinet/tcp.h>         //Provides declarations for tcp header
#include <netinet/ip.h>         //Provides declarations for ip header
#include <netinet/ip6.h>         //Provides declarations for ip6 header
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/if_ether.h>  //For ETH_P_ALL
#include <net/ethernet.h>       //For ether_header
#include <time.h>

/*
* Errors
*/
#define SNIFFING_DEV_ERR 11;
#define INVALID_ARGUMENTS 10;
#define PCAP_FINDALLDEVS_ERR 9;
#define INVALID_FETCH 8;
#define ERROR_FILTER_COMPILE 7;

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
*   Function for filtr compiling
*/
int compileFilter (pcap_t *sniffer, struct arguments arg, bpf_u_int32 ipAdr) {
    char *filter;
    bool stdFlag = arg.udp && arg.tcp && arg.icmp && arg.arp && arg.portFlag;   //If all true = stdFlag true
    std::vector<std::string> f;     //Vector for generating final string
    std::string fil = "";           
    bool filterReady = false;      //Flag if filter string is complited
    
    //Filter generating
    if (stdFlag) {      
        filter = &arg.port[0];
        filterReady = true;
    } else {
        if (arg.udp) {
            f.push_back("udp");
        }

        if (arg.tcp) {
            f.push_back("tcp");
        }

        if (arg.icmp) {
            f.push_back("icmp");
        }

        if (arg.arp) {
            f.push_back("arp");
        }
        
        if (arg.portFlag){      
            if (f.empty()) {                //If in arguments only port
                filter = &arg.port[0];
                filterReady = true;
            }
            f.push_back(arg.port);
        }

        if (f.empty()) {            //If noone parametr wasnt set
            fil = "udp or tcp or icmp or arp";
            filter = &fil[0];
        }
    }
    
    if (!filterReady && arg.portFlag) {     //Final string must start with ( if port is set
        fil = "(";
    }

    for (std::vector<std::string>::const_iterator i = f.begin(); i != f.end(); ++i) {       //Loop for generating string from vector params
        fil += *i;
        std::vector<std::string>::const_iterator elem = i;
        elem++;

        if (elem != f.end()) {  //If not the last element
            elem++;
            if (!(elem == f.end() && arg.portFlag)) {   //If not the last element and the next isnt port
                fil += " or ";
            } else if (elem == f.end() && arg.portFlag) {   //If the next elem is last and its port
                fil += ") and ";
            }
        }
    }
    
    if (!filterReady) {    //Check if filtr wasnt set, than copy string to char due to pcap_compile parametr
        filter = &fil[0];
    }

    struct bpf_program fp;
    if (pcap_compile(sniffer, &fp, filter, 0, ipAdr) == -1) {
        std::cerr << "Fail in filter compile" << std::endl;
        return ERROR_FILTER_COMPILE;
    }

    if (pcap_setfilter(sniffer, &fp) == -1) {
        std::cerr << "Fail in filter compile" << std::endl;
        return ERROR_FILTER_COMPILE;
    }

    return 0;
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
            if (arg.packetCount < 0 ) {
                arg.invalidArguments = true;
                return arg;
            }
            arg.n = true;

        } else if (argument == "-p") {
            i++;
            if (arg.n || i >= argc) {      //More then 1 --icmp
                arg.invalidArguments = true;
                return arg;
            }
            arg.port = "port ";
            arg.port += argv[i];
            arg.portFlag = true;

        } else {
            arg.invalidArguments = true;
            return arg;
        }
    }

    return arg;
}
/*
Function which returns ip of host
*/
std::string hostName(struct in_addr ip_addr) {
    char ip[1025];
    char node[1025];

    strcpy(ip, inet_ntoa(ip_addr));


    struct sockaddr_in sa;
	
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	 
	inet_pton(AF_INET, ip, &sa.sin_addr);
 
	int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
						  node, sizeof(node),
						  NULL, 0, NI_NAMEREQD);

    if (res) {
        std::string s1 = ip;
        return s1;
    } else {
        std::string s1 = node;
        return s1;
    }
}
/*
Function which returns ip of ipv6 host
*/
std::string hostNameIpv6(struct in6_addr ip_addr) {
    char ip[1025];
    char node[1025];
    inet_ntop(AF_INET6, &ip_addr, ip, 1025);
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;

    inet_pton(AF_INET6, ip, &sa.sin6_addr);

    int s = getnameinfo((struct sockaddr *)&sa, sizeof(sa), node, sizeof(node), NULL, 0, NI_NAMEREQD);

    if (s) {
        std::string ip1 = ip;
        return ip1;
    } else {
        std::string ip1 = node;
        return ip1;
    }
}

/*
Function to print udp packet
*/
void printUdp(const u_char *buffer, bool ip6) {
    unsigned short headerLen = 0;
    std::string srcIp, destIp;
    if (ip6) {
        struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
        srcIp = hostNameIpv6(iph->ip6_src);
        destIp = hostNameIpv6(iph->ip6_dst);
        headerLen = 40;
    } else {
        struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
        headerLen = iph->ip_hl * 4;
        srcIp = hostName(iph->ip_src);
        destIp = hostName(iph->ip_dst);
    }
    struct udphdr *udphd = (struct udphdr*)(buffer + headerLen + sizeof(struct ether_header));
    int udphdrLen =  sizeof(struct ether_header) + headerLen + sizeof(udphd);
    std::cout << srcIp << " : " << ntohs(udphd->uh_sport) << " > " << destIp << " : " << ntohs(udphd->uh_dport) << ", ";
}

/*
Callback function for pap_loop
*/
void handler (u_char *args, const struct pcap_pkthdr *pcapPk, const u_char* buffer) {
    struct ether_header *ethH = (struct ether_header *) buffer;
    std::cout <<"handle" << std::endl;

    int switchNum = 0;
    bool ip6 = false;

    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct ether_header *etherH = (struct ether_header *) buffer;

    char time[32];
    size_t len = strftime(time, sizeof(time), "%FT%T%z", localtime(&pcapPk->ts.tv_sec));
    char time1[] = {time[len - 2], time[len - 1], '\0' };
    sprintf(time + len - 2, ":%s", time1); 
    std::cout << time << " ";

    if (ntohs(etherH->ether_type) == ETHERTYPE_IPV6) {     // if ETHERTYPE is IPV6, flag is set to true
        struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
		switchNum = iph->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        ip6 = true;
    } else {
        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        switchNum = iph->protocol;
    }
    switch (iph->protocol) {
        case 1: //ICMP
            std::cout <<"icmp" << std::endl;
        break;
        case 6: //TCP
            std::cout <<"tcp" << std::endl;
        break;
        case 17: //UDP
            printUdp(buffer, ip6);
            
        break;
        default: //ACP
            std::cout <<"acp" << std::endl;

        break;
    }

    std::cout << "lenght " << int(pcapPk->len) << " bytes" << std::endl;

    int i;
    for (i = 0; i < int(pcapPk->len); i++) {
        printf("%02x ", buffer[i]);     //Using prinf here to convert byte
        if ((i + 1) % 16 == 0) {
            for (int j = i - 15; j != i + 1; j++) {
                if (buffer[j] > 127 || buffer[j] < 33){
                    std::cout << ".";
                } else {
                    printf("%c", buffer[j]);      //Using prinf here to convert byte
                }
            }
            std::cout << std::endl;
        }
    }

    for (int j = i; j % 16 != 0 ;j++) {
        std::cout << "   ";
    }

    for (int j = i - ((i + 1) % 16) + 1; j <= i - 1; j++) {
        if (buffer[j] > 127 || buffer[j] < 33){
            std::cout << ".";
        } else {
            printf("%c", buffer[j]);      //Using prinf here to convert byte
        }
    }
    std::cout << std::endl;
}
/*
*   Main program
*/
int main(int argc, char *argv[]) {
    struct arguments arg = argparse(argc, argv);
    char errbuf[PCAP_ERRBUF_SIZE]; //String for error messages


    //Checks if agruments was correct
    if (arg.invalidArguments) {
        std::cerr << "Invalid arguments" << errbuf << std::endl;
        return INVALID_ARGUMENTS;
    }

    std::cout << "Argument ok" << std::endl;
    //If -i wasn`t in arguments or -i was without interfaces
    if (arg.interface.empty()){
        pcap_if_t *allDevs, *dList;

        //Control if devises ok
        if (pcap_findalldevs(&allDevs, errbuf) == -1) {
            std::cerr << "Error in pcap_findalldevs" << errbuf << std::endl;
            return PCAP_FINDALLDEVS_ERR;
        }

        for (dList = allDevs; dList != NULL; dList = dList->next) {
            std::cout << dList->name << std::endl;
        }

        return 0;
    }

    bpf_u_int32 subMask, ipAdr;     //Submask and ip adress 
    char *interface = &arg.interface[0];
   
    //Fetch ip adress and subMask
    if(pcap_lookupnet(interface, &ipAdr, &subMask, errbuf) == -1) {
        std::cerr << "Immpossible to fetch ip adress or sub mask" << std::endl;
        return INVALID_FETCH;
    }

    //Sniffing devices
    pcap_t *sniffer = pcap_open_live(interface, BUFSIZ, 0, 1024, errbuf);
    if (sniffer == nullptr) {
        std::cerr << "Open device was failed, error message: " << errbuf << std::endl;
        return INVALID_FETCH;
    }
    struct bpf_program fp;
    if (compileFilter(sniffer, arg, ipAdr) != 0){
        return ERROR_FILTER_COMPILE;
    }

    pcap_loop(sniffer, arg.packetCount, handler, NULL);

    return 0;
}