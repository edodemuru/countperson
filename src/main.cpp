using namespace std;
#include <WiFi.h>
#include <Wire.h>

#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"

#include <assert.h>   
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string>

//#include <string.h>

#include "freertos/FreeRTOS.h"//kernel di sistema operativo in real-time usato nei dispositivi embedded
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include <vector>


#define BIT0 (1 << 0)

//Impostazioni per connettersi al server
#define SSID "edoHotspot"
#define PASSPHARSE "pippoinamerica"//ssid e password della rete a cui mi voglio collegare
#define MESSAGE "HelloTCPServer"
#define TCPServerIP "192.168.137.1" //ip del server nella rete in questione



//#define maxCh 13 //max Channel -> US = 11, EU = 13, Japan = 14
#define	WIFI_CHANNEL_MAX		(13)
#define	LED_GPIO_PIN			GPIO_NUM_4
//500 ms
//#define	WIFI_CHANNEL_SWITCH_INTERVAL	(5000)
//1 minute
//#define	WIFI_CHANNEL_SWITCH_INTERVAL	(60000)
#define	WIFI_CHANNEL_SWITCH_INTERVAL	(50000)


#define deltagrow 4         //termini per espansione lineare dell'array dinamico.//
#define deltashrink 6      // con condiz. necessaria : delta shrink>deltagrow.

// Current wifi channel
int curChannel = 1;
int level = 0;

String maclist[64][3]; 
int listcount = 0;


//static wifi_country_t wifi_country = {.cc="CN", .schan=1, .nchan=13, .policy=WIFI_COUNTRY_POLICY_AUTO};

String defaultTTL = "60"; // Maximum time (Apx seconds) elapsed before device is consirded offline

const wifi_promiscuous_filter_t filt={ 
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};



typedef struct { 
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

//Frame control flags
typedef struct {
     unsigned protocol:2;
     unsigned type:2;
     unsigned subtype:4;
     unsigned to_ds:1;
     unsigned from_ds:1;
     unsigned more_frag:1;
     unsigned retry:1;
     unsigned pwr_mgmt:1;
     unsigned more_data:1;
     unsigned wep:1;
     unsigned strict:1;
  } wifi_header_frame_control_t;

//Network packet header (MAC header)
typedef struct {
  wifi_header_frame_control_t frame_ctrl;
	//unsigned duration_id:16;
	uint8_t addr1[6]; /* receiver address */
	uint8_t addr2[6]; /* sender address */
	uint8_t addr3[6]; /* filtering address */
	unsigned sequence_ctrl:16;
	uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;


//Network packet
typedef struct {
  //Network packet header (Mac)
	wifi_ieee80211_mac_hdr_t hdr;
  //uint8_t payload [2];
	uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

vector<char> dataToSend;

//Callback function
static esp_err_t event_handler(void *ctx, system_event_t *event);
//Change channel function
static void wifi_sniffer_set_channel(uint8_t channel);
//Packet to string function
//static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
//Callback function
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);


static EventGroupHandle_t wifi_event_group;//variabile che identifica un gruppo di eventi wifi(RTOS)
const int CONNECTED_BIT = BIT0;
static const char *TAG="tcp_client";
void wifi_connect(){//collega la scheda alla rete wifi specificata
    wifi_config_t cfg = {
      .sta ={SSID,PASSPHARSE}
    };      
    /*wifi_config_t cfg = {
        .sta = {
            .ssid = SSID,
            .password = PASSPHARSE,
        },
    };*/
    ESP_ERROR_CHECK( esp_wifi_disconnect() );//mi disconnetto dalla rete alla quale eventualmente mi ero collegato in precedenza
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &cfg) );//configurazione
    ESP_ERROR_CHECK( esp_wifi_connect() );//mi connetto alla wifi
}



esp_err_t event_handler(void *ctx, system_event_t *event)
{
 switch(event->event_id) {//analizzo l'id relativo all'evento
    case SYSTEM_EVENT_STA_START://l'esp32 si è avviata
        wifi_connect();//collego l'esp32 alla wifi
        break;
    case SYSTEM_EVENT_STA_GOT_IP://l'esp32 ha ricevuto l'IP dall'access point a cui si è connesso
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);//setto il bit in modo da sbloccare i relativi task bloccati (???)
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED://l'esp32 si è disconnesso dall'access point
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);//pulisco i bit
        break;
    default:
        break;
    }
  return ESP_OK;
}

void tcp_client(){
    printf("tcp_client task started \n");
    //Socket inizialization
    struct sockaddr_in tcpServerAddr;
    tcpServerAddr.sin_addr.s_addr = inet_addr(TCPServerIP);
    tcpServerAddr.sin_family = AF_INET;
    tcpServerAddr.sin_port = htons( 8888 );//8888 is the port to which we connect
    int s, r;
    char recv_buf[64];//Reception buffer
    while(1){
        xEventGroupWaitBits(wifi_event_group,CONNECTED_BIT,false,true,100);
        s = socket(AF_INET, SOCK_STREAM, 0);//Socket's creation
        if(s < 0) { //Error in socket function
            ESP_LOGE(TAG, "... Failed to allocate socket.\n");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }
        printf( "... allocated socket\n");
         if(connect(s, (struct sockaddr *)&tcpServerAddr, sizeof(tcpServerAddr)) != 0) { //Connection to server
            // Code executed in case of error in connect function
            ESP_LOGE(TAG, "... socket connect failed errno=%d \n", errno);
            close(s);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            continue;
        }
        printf("...connected\n");
        // Pointer to char vector
        char* dataTosendChar = &dataToSend[0];
        //Send data
        if( write(s ,dataTosendChar, dataToSend.size()) < 0)
        {
            ESP_LOGE(TAG, "... Send failed \n");
            close(s);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            continue;
        }
        printf("... socket send success\n");
        do {
            bzero(recv_buf, sizeof(recv_buf));
            r = read(s, recv_buf, sizeof(recv_buf)-1);
            for(int i = 0; i < r; i++) {
                printf("%c",recv_buf[i]);
            }
        } while(r > 0);
        printf("... done reading from socket. Last read return=%d errno=%d\r\n", r, errno);
        close(s);
        printf("Sending complete\n");
        dataToSend.clear();
        return;
        
    }
}

//Function to insert channel number into char vector
void insertChanIntoData(int num){
    if(num<10){
        dataToSend.push_back(num +'0');
    }else{
        dataToSend.push_back('1');
        dataToSend.push_back((num-10)+'0');
    }
    dataToSend.push_back(' ');
}

//Function to insert rssi value into char vector
void insertRssiIntoData(int rssi){
     if(rssi>-10){
        dataToSend.push_back('-');
        dataToSend.push_back(rssi + '0');
    }else if(rssi>-100){
        char intchar[3];
        sprintf(intchar,"%d",rssi);
        dataToSend.push_back(intchar[0]);
        dataToSend.push_back(intchar[1]);
        dataToSend.push_back(intchar[2]);
    } else if(rssi == -100){
        char intchar[4];
        sprintf(intchar,"%d",rssi);
        dataToSend.push_back(intchar[0]);
        dataToSend.push_back(intchar[1]);
        dataToSend.push_back(intchar[2]);
        dataToSend.push_back(intchar[3]);

    }
    dataToSend.push_back(' ');
}

//Function to insert address into char vector
void insertAddrIntoData(uint8_t addr1,uint8_t addr2, uint8_t addr3, uint8_t addr4, uint8_t addr5, uint8_t addr6){
    char addrChar[18];
    sprintf(addrChar,"%02x:%02x:%02x:%02x:%02x:%02x",addr1,addr2, addr3, addr4, addr5, addr6);
    for(int i=0;i<17;i++){
        dataToSend.push_back(addrChar[i]);
    }

}


void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type) { //This is where packets end up after they get sniffed
  //Filter all packet types but MGMT
	if (type != WIFI_PKT_MGMT)
		return;

  // First layer: type cast the received buffer into our generic SDK structure
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
  // Second layer: define pointer to where the actual 802.11 packet is within the structure
	const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  // Third layer: define pointers to the 802.11 packet header and payload
	const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  // Pointer to the frame control section within the packet header
  const wifi_header_frame_control_t *frame_ctrl = (wifi_header_frame_control_t *)&hdr->frame_ctrl;

  

  //From now on, only probe request packet
  if(frame_ctrl->subtype != 4)
    return;

    //ssid length (25th byte of payload)
    uint8_t length = ppkt->payload[25];

//Print array and insert it into char vector
if(length!=0){
    printf("SSID=");
    for(uint8_t i = 0; i<length; i++){
      printf("%c",ppkt->payload[i+26]);
      dataToSend.push_back(ppkt->payload[i+26]);
    }
    printf(", ");
    }
else{
      printf("SSID=NONE, ");
      string n = "None";
      for(int i=0; i<n.size();i++){
          dataToSend.push_back(n[i]);
      }
    
    }
dataToSend.push_back(' ');

//Print address,rssi and channel
  printf("PACKET TYPE=PROBE, CHAN=%02d, RSSI=%02d,"
		" ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
		ppkt->rx_ctrl.channel,
		ppkt->rx_ctrl.rssi,
		/* ADDR1 */
		hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
		hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
		/* ADDR2 */
		hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
		hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
		/* ADDR3 */
		hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
		hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
	);

    insertChanIntoData(ppkt->rx_ctrl.channel);
    insertRssiIntoData(ppkt->rx_ctrl.rssi);
    insertAddrIntoData(hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);
    dataToSend.push_back(';');
    dataToSend.push_back('\n');
	

}

//===== SETUP =====//
void setup() {

  //Open a serial connection so we can output the result of the program
  Serial.begin(115200);
  //setup
  //nvs_flash_init();
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
   wifi_event_group = xEventGroupCreate();//create new group of events
   esp_log_level_set("wifi", ESP_LOG_NONE); // disable wifi driver logging
  tcpip_adapter_init();
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  //ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) );/* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  
    
  
  //Set promiscuous mode
  esp_wifi_set_promiscuous(true);
 
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler); //Register callback function
  gpio_set_direction(LED_GPIO_PIN, GPIO_MODE_OUTPUT);
  
  Serial.println("Configuration complete");


}

//Set channel
void
wifi_sniffer_set_channel(uint8_t channel)
{

	esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

//===== LOOP =====//
void loop() { 
    gpio_set_level(LED_GPIO_PIN,level^=1);
    printf("Start listening\n");
    vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);


    printf("End listening\n");
     //Disable promiscuous mode
     esp_wifi_set_promiscuous(false);
    //Set configuration for client   
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK( esp_wifi_start() );

    for(int i=0;i<dataToSend.size();i++){
        printf("%c",dataToSend[i]);
    }
    //Activate socket and send data
    tcp_client();
    printf("End communication with server\n");

    //reset settings
    esp_wifi_restore();

    //Enable promiscuous mode
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK( esp_wifi_start() );
    esp_wifi_set_promiscuous(true);

     
    
    //Change channel
    curChannel = (curChannel % WIFI_CHANNEL_MAX) + 1; //Set next channel
    wifi_sniffer_set_channel(curChannel); //Change channel
    printf("Current channel %d\n",curChannel);
    
    
    
}