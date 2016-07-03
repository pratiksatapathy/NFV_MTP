#include "hss.h"

string g_hss_ip_addr = "10.129.28.20";
//string rmc_path = "tcp:host=10.129.28.101,port=11100";
int g_hss_port = 6000;

Hss::Hss() {
	//g_sync.mux_init(mysql_client_mux);

	//ramcloud initialization
	rc_autn_info = new RMCMap<uint64_t,Authinfo>((char *)rmc_path.c_str(),"rc_autn_info");
	rc_loc_info = new RMCMap<uint64_t,uint32_t>((char *)rmc_path.c_str(),"rc_loc_info");

}
//making serializable
template<class Archive>
void Authinfo::serialize(Archive &ar, const unsigned int version)
    {
        ar & key_id & rand_num;
    }

void Hss::handle_mysql_conn() {
	/* Lock not necessary since this is called only once per object. Added for uniformity in locking */
	g_sync.mlock(mysql_client_mux);
	mysql_client.conn();
	g_sync.munlock(mysql_client_mux);
}

void Hss::get_autn_info(uint64_t imsi, uint64_t &key, uint64_t &rand_num) {

	RMCData<Authinfo> bundle = rc_autn_info->get(imsi);

	if(bundle.valid){
		key = ((Authinfo)(*(bundle.value))).key_id;
		rand_num = ((Authinfo)(*(bundle.value))).rand_num;

	}else{
		g_utils.handle_type1_error(-1, "ramcloud error: hss_getautninfo");

	}

}

void Hss::handle_autninfo_req(int conn_fd, Packet &pkt) {
	uint64_t imsi;
	uint64_t key;
	uint64_t rand_num;
	uint64_t autn_num;
	uint64_t sqn;
	uint64_t xres;
	uint64_t ck;
	uint64_t ik;
	uint64_t k_asme;
	uint64_t num_autn_vectors;
	uint16_t plmn_id;
	uint16_t nw_type;

	pkt.extract_item(imsi);
	pkt.extract_item(plmn_id);
	pkt.extract_item(num_autn_vectors);
	pkt.extract_item(nw_type);
	get_autn_info(imsi, key, rand_num);
	TRACE(cout << "hss_handleautoinforeq:" << " retrieved from database: " << imsi << endl;)
	sqn = rand_num + 1;
	xres = key + sqn + rand_num;
	autn_num = xres + 1;
	ck = xres + 2;
	ik = xres + 3;
	k_asme = ck + ik + sqn + plmn_id;
	TRACE(cout << "hss_handleautoinforeq:" << " autn:" << autn_num << " rand:" << rand_num << " xres:" << xres << " k_asme:" << k_asme << " " << imsi << endl;)
	pkt.clear_pkt();
	pkt.append_item(autn_num);
	pkt.append_item(rand_num);
	pkt.append_item(xres);
	pkt.append_item(k_asme);
	pkt.prepend_diameter_hdr(1, pkt.len);
	server.snd(conn_fd, pkt);
	TRACE(cout << "hss_handleautoinforeq:" << " response sent to mme: " << imsi << endl;)
}

void Hss::set_loc_info(uint64_t imsi, uint32_t mmei) {


	rc_loc_info->remove(imsi); //need a confirmation
	TRACE(cout << "hss_setlocinfo:" << " cleared previous entry "<< endl;)

	rc_loc_info->put(imsi,mmei);
	TRACE(cout << "hss_setlocinfo:" << "imsi:" << imsi<<" mmei:"<<mmei << endl;)

}

void Hss::handle_location_update(int conn_fd, Packet &pkt) {
	uint64_t imsi;
	uint64_t default_apn;
	uint32_t mmei;

	default_apn = 1;
	pkt.extract_item(imsi);
	pkt.extract_item(mmei);
	set_loc_info(imsi, mmei);
	TRACE(cout << "hss_handleautoinforeq:" << " loc updated" << endl;)
	pkt.clear_pkt();
	pkt.append_item(default_apn);
	pkt.prepend_diameter_hdr(2, pkt.len);
	server.snd(conn_fd, pkt);
	TRACE(cout << "hss_handleautoinforeq:" << " loc update complete sent to mme" << endl;)
}


Hss::~Hss() {

}
