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

#include <string.h>

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


#define BIT0 (1 << 0)
#define SSID "edoHotspot"
#define PASSPHARSE "pippoinamerica"//ssid e password della rete a cui mi voglio collegare
#define MESSAGE "HelloTCPServer"
#define TCPServerIP "192.168.137.1" //ip del server nella rete in questione

bool stop = false;



//#define maxCh 13 //max Channel -> US = 11, EU = 13, Japan = 14
#define	WIFI_CHANNEL_MAX		(13)
#define	LED_GPIO_PIN			GPIO_NUM_4
//500 ms
//#define	WIFI_CHANNEL_SWITCH_INTERVAL	(5000)
//1 minute
#define	WIFI_CHANNEL_SWITCH_INTERVAL	(60000)
//#define	WIFI_CHANNEL_SWITCH_INTERVAL	(5000)


#define deltagrow 4         //termini per espansione lineare dell'array dinamico.//
#define deltashrink 6      // con condiz. necessaria : delta shrink>deltagrow.

// Current wifi channel
int curChannel = 1;
int level = 0;

String maclist[64][3]; 
int listcount = 0;


//static wifi_country_t wifi_country = {.cc="CN", .schan=1, .nchan=13, .policy=WIFI_COUNTRY_POLICY_AUTO};

String KnownMac[10][2] = {  // Put devices you want to be reconized
  {"HPPC","7429AFE7D6A5"},
  {"Will-PC","E894Fffffff3"},
  {"TOMMASO","A09169B83748"},
  {"MARIA ROSARIA","A471744F5EA6"},
  {"NAME","MACADDRESS"},
  {"NAME","MACADDRESS"},
  {"NAME","MACADDRESS"},
  {"NAME","MACADDRESS"}
  
  
};

String defaultTTL = "60"; // Maximum time (Apx seconds) elapsed before device is consirded offline

const wifi_promiscuous_filter_t filt={ //Idk what this does
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};



typedef struct { // or this
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

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

//Network packet header
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
	wifi_ieee80211_mac_hdr_t hdr;
	uint8_t payload[2]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

/*typedef struct
{
  /*unsigned interval:16;
  unsigned capability:16;*/
  //unsigned tag_number:8;
  /*unsigned tag_length:8;
  char ssid[0];
  uint8_t rates[1];

} wifi_mgmt_probe_t;*/


//dynamic data structure to contain sniffed packets
struct Sarray{
	wifi_ieee80211_packet_t* vett; /*list of wifi_ieee80211 packets*/
	int i;    /* riempimento corrente, non Ã¨ l'indice; l'indice Ã¨ i-1 (dell'ultimo elemento) */
	int size; /* size */
};
typedef struct Sarray Tarray; 


Tarray a;  //global data structure variable

//function to manage data structure
Tarray array_create(int lung);
void array_destroy(Tarray* a);    
void array_resize(Tarray* a, int newlung); //resize dynamic array
void insert(Tarray* a, wifi_ieee80211_packet_t x);

//Callback function
static esp_err_t event_handler(void *ctx, system_event_t *event);
//Change channel function
static void wifi_sniffer_set_channel(uint8_t channel);
//Packet to string function
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
//Callback function
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);



//Implementazione prototipi array dinamico
Tarray array_create(int lung){

	Tarray arr;
	arr.vett = (wifi_ieee80211_packet_t* )malloc(lung*sizeof(wifi_ieee80211_packet_t));
	assert(lung==0 || a.vett!=NULL); //verifica che vettore Ã¨ diverso da NULL e che quindi Ã¨ stato allocato.
	//ho incluso la libreria assert sopra
  arr.i=lung;
	arr.size=lung;

	return arr;
}

void array_destroy(Tarray* a){

free(a->vett);
a->vett=NULL;
a->i=0;
a->size=0;


}

void array_resize(Tarray* a, int newlung){

/*algoritmo con espansione geometrica*/
if(newlung>a->size || newlung < (a->size-deltashrink)){
	int nuovo=newlung+deltagrow;
    a->vett=(wifi_ieee80211_packet_t *) realloc(a->vett,nuovo*sizeof(wifi_ieee80211_packet_t));
    assert(nuovo == 0 || a->vett!= NULL);
    a->size=nuovo;
}
	a->i=newlung;

}

void insert(Tarray* a, wifi_ieee80211_packet_t x){
  
  array_resize(a,a->i+1); 
  a->vett[a->i-1]=x;
  
}

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

//void tcp_client(void *pvParam){
void tcp_client(){
    printf("tcp_client task started \n");
    /*inizializzazione socket*/
    struct sockaddr_in tcpServerAddr;
    tcpServerAddr.sin_addr.s_addr = inet_addr(TCPServerIP);
    tcpServerAddr.sin_family = AF_INET;
    tcpServerAddr.sin_port = htons( 3010 );//3010 è la porta alla quale intendiamo collegarci
    int s, r;
    char recv_buf[64];//buffer di ricezione
    while(1){
        xEventGroupWaitBits(wifi_event_group,CONNECTED_BIT,false,true,100);
        s = socket(AF_INET, SOCK_STREAM, 0);//creo il socket
        if(s < 0) {//errore nella funzione socket
            ESP_LOGE(TAG, "... Failed to allocate socket.\n");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }
        printf( "... allocated socket\n");
         if(connect(s, (struct sockaddr *)&tcpServerAddr, sizeof(tcpServerAddr)) != 0) {//mi connetto al server
            //codice eseguito in caso di errore nella connect
            ESP_LOGE(TAG, "... socket connect failed errno=%d \n", errno);
            close(s);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            continue;
        }
        printf("...connected\n");
        if( write(s , MESSAGE , strlen(MESSAGE)) < 0)//invio il messaggio
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
                //putchar(recv_buf[i]);
                printf("%c",recv_buf[i]);
            }
        } while(r > 0);
        printf("... done reading from socket. Last read return=%d errno=%d\r\n", r, errno);
        close(s);
        printf("Sending complete\n");
        return;
        
    }
}


const char *
wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
	switch(type) {
	case WIFI_PKT_MGMT: return "MGMT";
	case WIFI_PKT_DATA: return "DATA";
	default:
	case WIFI_PKT_MISC: return "MISC";
	}
}

void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type) { //This is where packets end up after they get sniffed

  if(stop)
   return; 
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

  //insert(&a,*ipkt);

  //From now on, only probe request packet
  if(frame_ctrl->subtype != 4)
    return;

  //const wifi_mgmt_probe_t *probe_frame = (wifi_mgmt_probe_t*) ipkt->payload;
  /*char ssid[32] = {0};

    if (probe_frame->tag_length >= 32)
    {
      strncpy(ssid, probe_frame->ssid, 31);
    }
    else
    {
      strncpy(ssid, probe_frame->ssid, probe_frame->tag_length);
    }*/




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
  
	

}

static void initialise_wifi(void)//funzione di inizializzazione del modulo wifi
{
    esp_log_level_set("wifi", ESP_LOG_NONE); // disable wifi driver logging
    tcpip_adapter_init();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

//===== SETUP =====//
void setup() {

  //Open a serial connection so we can output the result of the program
  Serial.begin(115200);
   // setupOLED();
  //setup
  //nvs_flash_init();
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
   wifi_event_group = xEventGroupCreate();//creo un nuovo gruppo di eventi
   esp_log_level_set("wifi", ESP_LOG_NONE); // disable wifi driver logging
  tcpip_adapter_init();
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
	//ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) );/* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );

  //initialise_wifi();
  
    
  
  //Set promiscuous mode
  esp_wifi_set_promiscuous(true);
  //esp_wifi_set_promiscuous_filter(&filt); //Filter mac address??
 
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
    //a= array_create(0); //creo struttura dati array per contenere i pacchetti sniffati sul canale attuale su cui sto in ascolto 
    gpio_set_level(LED_GPIO_PIN,level^=1);
    printf("Start listening\n");
    vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);


 
  /*for(int h=0;h<a.i;h++){*/
   //stampo i-esimopacchetto matchato su quel canale
    /*wifi_ieee80211_packet_t ipkt = a.vett[h];
	 wifi_ieee80211_mac_hdr_t hdr = ipkt.hdr; 

      printf("PACKET MALNATI"
		" ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n", */
		
		/* ADDR1 */
		 /*hdr.addr1[0],hdr.addr1[1],hdr.addr1[2],
		hdr.addr1[3],hdr.addr1[4],hdr.addr1[5], */
		/* ADDR2 */
		 /*hdr.addr2[0],hdr.addr2[1],hdr.addr2[2],
		hdr.addr2[3],hdr.addr2[4],hdr.addr2[5], */
		/* ADDR3 */
		 /*hdr.addr3[0],hdr.addr3[1],hdr.addr3[2],
		hdr.addr3[3],hdr.addr3[4],hdr.addr3[5]
     ); 
	}*/
    //dopo aver inviato i pacchetti faccio la destroy
     /*array_destroy(&a); */

    printf("End listening\n");
     //Disable promiscuous mode
     esp_wifi_set_promiscuous(false);

    //Set configuration for client   
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA));
    //xTaskCreate(&tcp_client,"tcp_client",4048,NULL,5,NULL);//creo un task e lo aggiungo alla lista dei task pronti ad essere eseguiti
    tcp_client();
    printf("End communication with server\n");

    //Enable promiscuous mode
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
     esp_wifi_set_promiscuous(true);
     
    
    //Change channel
    curChannel = (curChannel % WIFI_CHANNEL_MAX) + 1; //Set next channel
    wifi_sniffer_set_channel(curChannel); //Change channel
    printf("Current channel %d\n",curChannel);
    
    /*stop = true;
    printf("End listening\n");
    //xTaskCreate(&tcp_client,"tcp_client",4048,NULL,5,NULL);//creo un task e lo aggiungo alla lista dei task pronti ad essere eseguiti
    tcp_client();
    stop = false;*/
    //esp_wifi_set_promiscuous(true);
    //delay(500);
    
}