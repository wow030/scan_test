#include <wchar.h>
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
#include <stack>
#include <vector>
#include <sstream>
#include <cstring>
#include "sha256.h"
#include "hmac-sha1.h"
#include <openssl/hmac.h>
#include <cmath>
#include <iomanip>
using namespace std;
//

string hmacHex(string key, string msg)
{
    unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    HMAC_Init_ex(&hmac, &key[0], key.length(), EVP_sha256(), NULL);
    HMAC_Update(&hmac, (unsigned char*)&msg[0], msg.length());
    unsigned int len = 32;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    std::stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < len; i++)
    {   
        ss << hex << setw(2)  << (unsigned int)hash[i];
    }

    return (ss.str());
}

void simpleadvertise( string sha256_sttring );

bool if_count_bit_full ( bool* count_bit, int len ) {
	int count = 0;
	cout << "---------------" << endl;
	cout << len << endl;
	cout << "=---------------" << endl;

	for ( int i = 0; i < len; ++i ) {
		if ( count_bit[i] == true )
			count++;
		if ( count == (len + 1) )
			return true;
	}

	return false;

}

// from advertise.c
// 123
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

int main()
{
        int b = 0;
	scanf( "%d", &b );
	int ret, status;

	// Get HCI device.

	const int device = hci_open_dev(hci_get_route(NULL));
	if ( device < 0 ) { 
		perror("Failed to open HCI device.");
		return 0; 
	}

	// Set BLE scan parameters.
	
	le_set_scan_parameters_cp scan_params_cp;
	memset(&scan_params_cp, 0, sizeof(scan_params_cp));
	scan_params_cp.type 			= 0x00; 
	scan_params_cp.interval 		= htobs(0x0010);
	scan_params_cp.window 			= htobs(0x0010);
	scan_params_cp.own_bdaddr_type 	= 0x00; // Public Device Address (default).
	scan_params_cp.filter 			= 0x00; // Accept all.

	struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS,     LE_SET_SCAN_PARAMETERS_CP_SIZE, &status, &scan_params_cp);
	
	ret = hci_send_req(device, &scan_params_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set scan parameters data.");
		return 0;
	}

	// Set BLE events report mask.

	le_set_event_mask_cp event_mask_cp;
	memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
	int i = 0;
	for ( i = 0 ; i < 8 ; i++ ) event_mask_cp.mask[i] = 0xFF;

	struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &status, &event_mask_cp);
	ret = hci_send_req(device, &set_mask_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set event mask.");
		return 0;
	}

	// Enable scanning.

	le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable 		= 0x01;	// Enable flag.
	scan_cp.filter_dup 	= 0x00; // Filtering disabled.

	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);

	ret = hci_send_req(device, &enable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to enable scan.");
		return 0;
	}

	// Get Results.

	struct hci_filter nf;
	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	if ( setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0 ) {
		hci_close_dev(device);
		perror("Could not set socket options\n");
		return 0;
	}

	printf("Scanning....\n");

	uint8_t buf[HCI_MAX_EVENT_SIZE];
	evt_le_meta_event * meta_event;
	le_advertising_info * info;
	int len;
	int total_len = 0;
	int length_count = 0;
	len = read(device, buf, sizeof(buf));
	//printf("++++++++++++++++++++++\n");
	total_len = (int)buf[26]; // length index in packet is 26
	//printf( "  k : %d\n", k );
    //total_len = total_len;
    vector<uint8_t> uint8_t_vector(total_len,0);
    printf( "total_len = %d\n", total_len );
	int count = 0;
    int packet_count = 0;
    int packet_num;
    
    if (total_len <= 18) {
        packet_num = 1;
    }
    else {
        packet_num = 1 + ceil( (float)( total_len - 18 ) / 19 );
    }

    cout << "totallen ======" << total_len << endl;
    cout << (int)buf[25] - 47 << "~" << endl;
    bool count_bit[packet_num] = {false};
    // for first packet
    cout << (int)buf[25] - 48 + 1 << endl;
    if ( (int)buf[25] - 48 + 1 == packet_num  ) {
        // just one packet and it is the last one
        int begin_count = 27;
        int index_count = 0;
        while ( index_count < total_len ) {
            uint8_t_vector.at(index_count) = buf[begin_count++];
            ++index_count;
        }
    }
    else {
        // more than two packet
        int begin_count = 27;
        int index_count = 0;
        while ( index_count < 18 ) {
            cout << index_count << " : " << buf[begin_count] << endl;
            uint8_t_vector.at(index_count) = buf[begin_count++];
            ++index_count;
            cout << "hello" << endl;
        }
    }

    cout << "fist packet end" << endl;
    cout << "packet num :" << packet_num << endl;
	cout << "(int)buf[25] - 48: " << (int)buf[25] - 48 << endl;
    packet_count++;
    count_bit[(int)buf[25] - 48] = true;
    //cout << (int)buf[25] - 48 << endl;
    for ( int i = 0; i < 50; i++ )
        printf(" %d > %02x\n",i,buf[i]);
    len = read(device,buf,sizeof(buf));
	
    while ( if_count_bit_full(count_bit,packet_num) == false ) {
        cout << "sdfsdffergregegegegege" << endl;
        cout << packet_count << endl;
        for ( int k = 0; k < 50; k++  )
            printf( "%c ",buf[k] );
        cout << endl;
        if ( count_bit[(int)buf[25] - 48] == false  ) {
            cout << "get in" << endl;
            if ( (int)buf[25] - 48 + 1 == packet_num  ) {
                cout << "packet number: " << (int)buf[25] - 48 + 1 << endl;
                // if it is the last packet
                cout << "error in last packet" << endl;
                int begin_count = 26;
                int index_count = 0;
                int index_in_vector = 18 + ((int)buf[25]-49)*19;
                cout << "total_len: " << total_len << endl;
                cout << "index_in_vector: " << index_in_vector << endl;
                while ( index_in_vector < total_len  ) {
                    uint8_t_vector.at(index_in_vector) = buf[begin_count];
                    ++begin_count;
                    ++index_in_vector;
                    cout << "always loop1" << endl;
                }

                break;
            }
            else {
                cout << "packet number:  " << (int)buf[25] - 48 + 1 << endl;
                int begin_count = 26;
                int index_count = 0;
                
                int index_in_vector = 18 + ((int)buf[25]-49)*19;
                cout << "packet_len: " << total_len << endl;
                cout << "index_in_vector: " << index_in_vector << "index_in_vector - 1: " << (int)buf[25] - 48 << endl;
                while ( index_count < 19 ) {
                    cout << index_in_vector << " : " << buf[begin_count] << endl;
                    uint8_t_vector.at(index_in_vector) = buf[begin_count];
                    index_count++;
                    begin_count++;
                    ++index_in_vector;
                    cout << "always loop" << endl;
                }
            }
            cout << "==== packet count =====" << endl; 
            packet_count++;   
            count_bit[(int)buf[25]-48] = true;
        }
        
        //count_bit[(int)buf[25]-48] = true;
		memset(&buf,0,sizeof(buf));
		len = read(device,buf,sizeof(buf));
	}

	cout << "\n" << "===========msg get==================" << endl;
	cout << "received size: " << uint8_t_vector.size() << endl;
	string input_string;
	for ( int j = 0; j < uint8_t_vector.size(); j++ ) {
		input_string += (char)uint8_t_vector.at(j);
		printf( "%d > %c\n",j ,uint8_t_vector.at(j) );
	}

	cout << "\n" << "===========msg get==================" << endl;
	printf("\n");


    // stop here~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    uint8_t LN1[4] = { 0x43,0x59,0x43,0x55 };
	cout << "input string--------- size" << endl;
	cout << input_string.size() << endl;
	cout << "input string---------- size" << endl;
	input_string[input_string.size() - 1] = (char)(input_string[input_string.size() - 1] | LN1[3]);
	input_string[input_string.size() - 2] = (char)(input_string[input_string.size() - 2] | LN1[2]);
	input_string[input_string.size() - 3] = (char)(input_string[input_string.size() - 3] | LN1[1]);
	input_string[input_string.size() - 4] = (char)(input_string[input_string.size() - 4] | LN1[0]);

    uint8_t kn1[] = "ABCD";
    //uint8_t digest[41];
	// data = input_string
    cout << "kn1 = ABCD" << endl;
    cout << "LN1 = CYCU" << endl;
    vector<uint8_t> mVector(input_string.begin(),input_string.end());
    uint8_t *p = &mVector[0];
    // the correct one 
    string sha1256 = hmacHex( "ABCD",input_string );
    // the correct one
   // hmac_sha1_hex( digest, kn1, sizeof(kn1)/sizeof(uint8_t), p, sizeof(p)/sizeof(uint8_t) );	
    //printf("HMAC-SHA1 = : %s\n", digest);


    //string sha256_output = strin();
    //
	//string sha256_output = sha256(input_string);
	//cout << "sha256>>>>>" << sha256_output << endl
    //char digest_char[41];
    //for (int fuck = 0; fuck < 41; fuck++) {
    //    digest_char[fuck] = (unsigned char)digest[fuck];
    //}
    //string sha1_output(digest_char);
    
    string sha1256_32;
    for ( int i = 0; i < 32; ++i ) {
	sha1256_32 += ( sha1256[i*2] << 4 ) | ( sha1256[i*2 + 1] ); 
    }

    cout << "sha1256_output = " << sha1256 << endl;
    //setlocale(LC_ALL, "");
    //printf("sha1256_32: %s", sha1256_32);
    hci_close_dev(device);
    simpleadvertise( sha1256_32 );
    hci_close_dev(device);

	/*while ( 1 ) {
		len = read(device, buf, sizeof(buf));
		if ( len >= HCI_EVENT_HDR_SIZE ) {
			meta_event = (evt_le_meta_event*)(buf+HCI_EVENT_HDR_SIZE+1);
			if ( meta_event->subevent == EVT_LE_ADVERTISING_REPORT ) {
				uint8_t reports_count = meta_event->data[0];
				void * offset = meta_event->data + 1;
				while ( reports_count-- ) {
					info = (le_advertising_info *)offset;
					char addr[18];
					ba2str(&(info->bdaddr), addr);
					printf("%s - RSSI %d\n", addr, (char)info->data[info->length]);
					offset = info->data + info->length + 2;
				}
			}
		}
	}*/

	// Disable scanning.

	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable = 0x00;	// Disable flag.

	struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
	ret = hci_send_req(device, &disable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to disable scan.");
		return 0;
	}

	hci_close_dev(device);
	cout << "close dev" << endl;	
	return 0;
}

void simpleadvertise( string sha256_string ){
	int ret, status;
    
    cout << "======start to advertise======" << endl;
	// Get HCI device.

	const int device = hci_open_dev(hci_get_route(NULL));
	if ( device < 0 ) { 
		perror("Failed to open HC device.");
		return; 
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
		return;
	}

	// Set BLE advertisement data.	
	int packet_count = 0;
	int sequence = 0;
	char* input_char;

	while ( packet_count < sha256_string.size() ){
		string sub_input;
		if ( packet_count == 0 ) {
			stringstream ss;
			int i = 0;
			int index = 0;
			uint8_t mac[6] = {0xB8,0x27,0xEB,0xAB,0xBA,0x26};
			for ( i = 0; i< 6; ++i )
				sub_input += (char)mac[i];
			ss << sequence;
			sub_input += ss.str();
			stringstream ss_1;
			char len_p;
            cout << "length = " << sha256_string.size();
			len_p = sha256_string.size();
			cout << "len_p:" << len_p << endl;
			sub_input += len_p;
			if ( sha256_string.size() >= 18 ) {
				sub_input += sha256_string.substr(0,18);
				packet_count += 18;
			} 
			else {
				sub_input += sha256_string.substr(0,sha256_string.size());
				packet_count += sha256_string.size();
			}

			cout << sub_input << endl;
		
		}
		else {
			int i = 0;
			uint8_t mac[] = {0xB8, 0x27, 0xEB, 0xAB, 0xBA, 0x26};
			for ( i = 0; i< 6; ++i ) {
				sub_input += (char)mac[i];
			}

			stringstream ss;
			ss << sequence;
			sub_input+=ss.str();
			if ( sha256_string.size() - packet_count < 19 ) {
				sub_input += sha256_string.substr( packet_count );
				packet_count += sha256_string.size();
			}
			else {
				sub_input += sha256_string.substr( packet_count, 19 );
				packet_count += 19;
			}
	
			cout << sub_input << endl;
		}

		input_char = new char[sub_input.size() + 1];
		memcpy( input_char, sub_input.c_str(), sub_input.size() + 1 );
		cout << "input_char : " << input_char << endl;
		le_set_advertising_data_cp adv_data_cp = ble_hci_params_for_set_adv_data(input_char);
	
		struct hci_request adv_data_rq = ble_hci_request(
			OCF_LE_SET_ADVERTISING_DATA,
			LE_SET_ADVERTISING_DATA_CP_SIZE, &status, &adv_data_cp);

		ret = hci_send_req(device, &adv_data_rq, 1000);
		if ( ret < 0 ) {
			hci_close_dev(device);
			perror("Failed to set advertising data.");
			return;
		}

		// Enable advertising.

		le_set_advertise_enable_cp advertise_cp;
		memset(&advertise_cp, 0, sizeof(advertise_cp));
		advertise_cp.enable = 0x01;

		struct hci_request enable_adv_rq = ble_hci_request(
			OCF_LE_SET_ADVERTISE_ENABLE,
			LE_SET_ADVERTISE_ENABLE_CP_SIZE, &status, &advertise_cp);

		ret = hci_send_req(device, &enable_adv_rq, 1000);
		if ( ret < 0 ) {
			hci_close_dev(device);
			perror("Failed to enable advertising.");
			return;
		}

		sub_input.clear();
		sequence += 1;
		delete []input_char;
		usleep(5500000);
	} 


	hci_close_dev(device);
	
	cout << "end of advertise" << endl;
	return;



} 
