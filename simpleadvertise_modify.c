#include <iostream>
#include <stdlib.h>
#include <errno.h>
#include <curses.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <vector>
#include <cstring>
#include <sstream>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cmath>
 #include <time.h>
#define PORT "83"

#define MAXDATASIZE 100
#define thread_N 100
using namespace std;



/*void webserver() {
	int sockfd, numbytes;
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	char *hostname = "192.168.0.5";
	memset(&hints, 0, sizeof(hints));
	hints.ai_family(AF_UNSPEC);
	hints.ai_socktype = SOCK_STREAM;
	if ( (rv = getaddrinfo(hostname, PORT, &hints, &servinfo)) != 0 ) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return;
	}
	
	for ( p = serinfo; p != NULL; p = p->ai_next ) {
		if ( (sockfd = socket(p->ai_family, p->ai_socktypem, p->ai_protocal)) == -1 ) {
			perror( "client: socket" );
			continue;
		}
		if ( connect(sockfd, p->ai_addr, p->ai_addrlen) == -1 ) {
			close(sockfd);
			perror("client: connect");
			continue;
		}
		
		break;
	}
	if ( p == NULL ) {
		fprintf( stderr, "client : failed to connect\n" );
		return; // return 2
	}
	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),s ,sizeof s);
	printf( "client connect to %s\n", s );
	freeaddrinfo(servinfo);
	if ( ( numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0 )) == -1 ) {
		perror("recv");
		exit(1);
	}
		
	buf[numbytes] = '\0';
	printf( "client: received '%s'\n", buf );
	
	close(sockfd);
	return 0;
}*/
int advertise_1( string , uint8_t[] );

void webserver( char* buffer ) {
	int create_socket, new_socket;
	socklen_t addrlen;
	int bufsize = 1024;
	struct sockaddr_in address;
	
	if ((create_socket = socket(AF_INET, SOCK_STREAM,0)) > 0) {
		printf( "socket created\n" );
	}
	
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(1500);

	if ( bind( create_socket, (struct sockaddr *) &address, sizeof(address) ) == 0 ) {
		printf( "Binding Socket\n" );
	}

	if ( listen(create_socket, 10) < 0 ) {
		perror("server: listen");
	}
	
	if ( ( new_socket = accept(create_socket,(struct sockaddr *) &address, &addrlen)) < 0 ) {
		perror("server: accept");
		exit(1);
	}
	
	if ( new_socket > 0 ){
		printf( "The client is connected...\n" );

	}

	recv( new_socket, buffer, bufsize, 0 );
	printf( "buffer get : %s\n", buffer );
	//write( new_socket, "fuck you", 8 );
	//close(new_socket);
	close(create_socket);

}

void simpleadvertise(string,int,string,uint8_t[],int,int);

void webserver_send( char* & buf_webserver ) {
	int sockfd = 0, n = 0;
	char recvBuff[1024];
	struct sockaddr_in serv_addr;

	memset( recvBuff, '\0', sizeof recvBuff );
	if ( (sockfd = socket(AF_INET, SOCK_STREAM,0)) < 0 ) {
		printf( "\n Error : Could not create socket \n" );
		return ;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(34567);

	if (inet_pton(AF_INET, "192.168.0.2", &serv_addr.sin_addr) <= 0) {
		printf("\n inet_pton error coured\n");
		return;
	}

	if ( connect( sockfd, ( struct sockaddr * )&serv_addr, sizeof serv_addr ) < 0 ) {
		printf( "\n Error : Connet Failed \n" );
		return;
	}
	
	string buff = "GET /result.txt/";
    string context(buf_webserver);
    buff += context + " HTTP/1.1\n";
	string buff1 = "Content-Type: text/html\n\n";
	write( sockfd, buff.c_str(), buff.size() );
	write( sockfd, buff1.c_str(),buff1.size());
	
	int count = 0;
	//usleep(500000);
	while ( ( n = read(sockfd, recvBuff, sizeof(recvBuff) - 1)) > 0 ) {
		printf( "\n===============%d==============\n",count++ );
		if ( fputs(recvBuff, stdout) == EOF ) {
			printf( "\n Error : Fputs error\n" );
		}
	}

	printf( "\n--------------------------\n" );	
	int index = strlen(recvBuff) - 1; // the last one is '\0'

	while ( recvBuff[index] != '\n' ) {
		printf( "%d : %c\n", index, recvBuff[index--] );
	}

	printf( "receive over\n" );
	if ( n < 0 ) {
		printf( "\n Read error \n" );
	}

	strcpy( buf_webserver, recvBuff );
	return;

} 

void simplescan( vector<uint8_t> & );

struct hci_request ble_hci_request(uint16_t ocf, int clen, void * status, void * cparam)
{
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = ocf;
	rq.cparam = cparam;
	rq.clen = clen;
	rq.rparam = status;
	rq.rlen = 1;
	return rq;
}

le_set_advertising_data_cp ble_hci_params_for_set_adv_data(char * name)
{
	int name_len = strlen(name);

	le_set_advertising_data_cp adv_data_cp;
	memset(&adv_data_cp, 0, sizeof(adv_data_cp));

	// Build simple advertisement data bundle according to:
	// - ​"Core Specification Supplement (CSS) v5" 
	// ( https://www.bluetooth.org/en-us/specification/adopted-specifications )

	adv_data_cp.data[0] = 0x02; // Length.
	adv_data_cp.data[1] = 0x01; // Flags field.
	adv_data_cp.data[2] = 0x01; // LE Limited Discoverable Flag set

	adv_data_cp.data[3] = name_len + 1; // Length.
	adv_data_cp.data[4] = 0x09; // Name field.
	memcpy(adv_data_cp.data + 5, name, name_len);

	adv_data_cp.length = 5 + strlen(name);

	return adv_data_cp;
}

int return_hex_in_dec( char c ) {
	char _table[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	int count = 0;
	while ( count < 16 ) {
		if ( c == _table[count] )
			return count;
		count++;
	}

	return -1;
}


int main()
{
	string sub_webserver_string;
	while (1) {
		int buf_webserver_size = 1024;
		char* buf_webserver = ( char * )malloc( buf_webserver_size );	
		webserver( buf_webserver );
		string buf_webserver_string(buf_webserver);
		cout << "----------------recv form webserver-----------------\n";
		cout << "msg recv from webserver is : " << strlen(buf_webserver) << endl;			
		cout << "----------------recv form webserver-----------------\n";
		
		// get MAC to node
		uint8_t mac_to_node[6]; // reverse version
		int index = strlen(buf_webserver) - 12;
		for ( int i = 0; i < 12; i+=2 ) {
			int index_mac = 0;
			index_mac = i / 2;
			mac_node[index_mac] = ( return_hex_in_dec(buf_webserver[index + i]) << 4 ) | ( return_hex_in_dec(buf_webserver[index + i + 1]) );
			printf( "%02x :", mac_node[index_mac] );
		}
		cout << endl;
		
		sub_webserver_string = buf_webserver_string.substr(0,strlen(buf_webserver) - 12);
		// starting advertise
		cout << "----------------starting advertising-----------------\n";
		advertise_1(sub_webserver_string,mac_to_node);
		cout << "----------------end advertising-----------------\n";
		
		
		vector<uint8_t> uint8_t_vector_second;
		
		int packet_total_num = 0;
		int packet_count = 0;
		clock_t start = 0, finish = 0;
		bool if_first_packet_recv = false;
		
		start = clock();
		while (packet_count < packet_total_num) {
			finish = clock();
			if ( (double)(finish - start) / CLOCKS_PER_SEC < 10.0) { // less than 20s
				simplescan(packet_count,packet_total_num,if_first_packet_recv);
			}
			else {
				perror("time out\n");
				exit(1);
			}
		}
		


void *worker_thread(void *arg)
{
        printf("This is worker_thread #%ld\n", (long)arg);
        pthread_exit(NULL);
}

int main()
{
        pthread_t thread_scan[thread_N];

        long id;
        for(id = 1; id <= thread_N; id++) {
                int ret =  pthread_create(&thread_scan[id], NULL, &scan_thread, (void*)id);
                if(ret != 0) {
                        printf("Error: pthread_create() failed\n");
                        exit(EXIT_FAILURE);
                }
        }

        pthread_exit(NULL);
}
		
		
	}

	
	vector<uint8_t> uint8_t_vector_second;
	simplescan( uint8_t_vector_second );
	string data;

	cout << "================= received from node =================" << endl;
	cout << "dat length:" << uint8_t_vector_second.size() << endl;	
	for ( int k = 0; k < uint8_t_vector_second.size(); k++ )
		data += char(uint8_t_vector_second.at(k));
	data = sub_webserver_string + data;

	cout << "total input = " << data << endl;

	cout << "================== received from node ================" << endl;	

        cout << "==============advertise twice==================\n" << endl;
    simpleadvertise( data, device,sub_webserver_string,mac_node,status,ret );
	// stransfer to wifi~~~~~~~~~~~~~~~~~~~~~~
    cout << "=====end advertise twice" << endl;

    cout << "========scan twice======" << endl;
    hci_close_dev(device);
	vector<uint8_t> uint8_t_vector_third;
    simplescan(uint8_t_vector_third);
    cout << "======== end of scan twice=====" << endl;
    hci_close_dev(device);
	cout << "close_dev" << endl;
	
    cout << "==== send to verify server==" << endl;
    string data_to_server_string;
    for (int j = 0; j < uint8_t_vector_third.size();++j) {
        data_to_server_string += uint8_t_vector_third.at(j);
    }

    char* data_to_server_char = const_cast<char*>(data_to_server_string.c_str());
    webserver_send(data_to_server_char); 
    cout << "send to verify server====" << endl;
    return 0;
}

int advertise_1( string sub_webserver_string, uint8_t mac_to_node[] )
{
	int ret, status;

	// Get HCI device.

	const int device = hci_open_dev(hci_get_route(NULL));
	if ( device < 0 ) { 
		perror("Failed to open HC device.");
		return 0; 
	}

	// Set BLE advertisement parameters.
	
	le_set_advertising_parameters_cp adv_params_cp;
	memset(&adv_params_cp, 0, sizeof(adv_params_cp));
	adv_params_cp.min_interval = htobs(0x0800);
	adv_params_cp.max_interval = htobs(0x0800);
	adv_params_cp.chan_map = 7;
	
	struct hci_request adv_params_rq = ble_hci_request(
		OCF_LE_SET_ADVERTISING_PARAMETERS,
		LE_SET_ADVERTISING_PARAMETERS_CP_SIZE, &status, &adv_params_cp);
	
	ret = hci_send_req(device, &adv_params_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set advertisement parameters data.");
		return 0;
	}
	
	int packet_count = 0;
	int sequence = 0;
	char* input_char;	
	// start bluetooth
    cout << "length: " << sub_webserver_string.size() << endl;	
	// cin >> input;
	// send data

	while ( packet_count < sub_webserver_string.size() ) {
		//printf( "%02x  %02x  %02x\n", mac_node[0],mac_node[1], mac_node[2] );
		string sub_input;
		if ( packet_count == 0 ) {
			stringstream ss;
			int i = 0;
			//int index = 0;
			uint8_t mac[6]; // -=========================================
			for ( int i = 0; i < 6; i++ )
				mac[i] = mac_node[6 - i - 1];
			for ( i = 5; i >=0; --i  ) {
				sub_input += ( unsigned char)mac[i];
			}

			printf( "%02x %02x %02x %02x %02x %02x\n", mac[0],mac[1], mac[2], mac[3], mac[4], mac[5] );
            //char len_p;

			//sub_input += "B827EBABBA26";
			ss << sequence;
			sub_input += ss.str();
			//stringstream ss_1;
			char len_p;
			len_p = sub_webserver_string.size();
	                cout << "total length:" << (int)len_p << endl;
			sub_input += len_p;
			if ( sub_webserver_string.size() >= 18 ) {
				sub_input += sub_webserver_string.substr(0,18);
				packet_count += 18;
			}
			else {
				sub_input += sub_webserver_string.substr(0,sub_webserver_string.size());
				packet_count += sub_webserver_string.size();
			}
			cout << "sequence: " << sequence << " >>" << sub_input << endl;
		}
		else {
			//sub_input = sub_input + "B827EBABBA26";
			int i = 0;
			uint8_t mac[6];
			for ( int i = 0; i < 6; ++i )
				mac[i] = mac_node[6 - i - 1];
			for ( i = 5; i >= 0; --i )
				sub_input += ( unsigned char )mac[i];

			printf( "%02x %02x %02x %02x %02x %02x\n", mac[0],mac[1], mac[2], mac[3], mac[4], mac[5] );


			stringstream ss;
			ss << sequence;
			sub_input += ss.str();
			if ( sub_webserver_string.size() - packet_count < 19 ) {
				sub_input += sub_webserver_string.substr( packet_count );
				packet_count += sub_webserver_string.size();
			}
			else {
				//cout << "over packet size++++++++++++" << endl;
				
				sub_input += sub_webserver_string.substr( packet_count, 19 );
				packet_count = packet_count + 19;
				//cout << "packet_count : " << packet_count << endl;
			}
			cout << "sequence: " << sequence << " >>" << sub_input << endl;
		}

    		input_char = new char[sub_input.size() + 1];
    		memcpy(input_char, sub_input.c_str(), sub_input.size() + 1);
		// Set BLE advertisement data.
		cout << "input_char : " << input_char << endl;
		le_set_advertising_data_cp adv_data_cp = ble_hci_params_for_set_adv_data(input_char);
        
		struct hci_request adv_data_rq = ble_hci_request(
			OCF_LE_SET_ADVERTISING_DATA,
			LE_SET_ADVERTISING_DATA_CP_SIZE, &status, &adv_data_cp);

		ret = hci_send_req(device, &adv_data_rq, 1000);
        
        /*
        for ( int j = 0; j < 10; j++  ) {
            cout << "sequence : " << sequence << endl;
            ret = hci_send_req(device,&adv_data_rq,1000);
        }
        */
        
    
    //ret = hci_send_req(device, &adv_data_rq,1000);
		if ( ret < 0 ) {
			hci_close_dev(device);
			perror("Failed to set advertising data.");
			return 0;
		}

		// Enable advertising.

		le_set_advertise_enable_cp advertise_cp;
		memset(&advertise_cp, 0, sizeof(advertise_cp));
		advertise_cp.enable = 0x01;

		struct hci_request enable_adv_rq = ble_hci_request(
			OCF_LE_SET_ADVERTISE_ENABLE,
			LE_SET_ADVERTISE_ENABLE_CP_SIZE, &status, &advertise_cp);

		for ( int j = 0; j < 9527; j++ ) {		
			ret = hci_send_req(device, &enable_adv_rq, 1000);
		}
		if ( ret < 0 ) {
			hci_close_dev(device);
			perror("Failed to enable advertising.");
			return 0;
		}

		sub_input.clear();	
		sequence += 1;
		delete [] input_char;
       		 //usleep(500000);
	        cout << endl;
		
	}

    close(device);
}
