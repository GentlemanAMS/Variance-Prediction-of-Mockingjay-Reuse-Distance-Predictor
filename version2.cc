#include "cache.h"
#include "ooo_cpu.h"
#include <unordered_map>
#include <stdlib.h>

#define NUM_CORE 1
#define LLC_SETS NUM_CORE*2048
#define LLC_WAYS 16

#include<iostream>
#include<vector>
#include<unordered_set>
#include<inttypes.h>
#include<cmath> 
#include<fstream>
#include<string>
#include<sstream>

#define ANALYSIS_RDP 1
#define ANALYSIS_ETA 0
#define ETR_UPDATE 1
#define LRU 1

using namespace std;

constexpr int LOG2_LLC_SET = log2(LLC_SETS);
constexpr int LOG2_LLC_SIZE = LOG2_LLC_SET + log2(LLC_WAYS) + LOG2_BLOCK_SIZE;

class SamplingCacheline{
    public:
        uint64_t signature;
        uint64_t timestamp;
        bool valid;
        uint64_t tag;

        SamplingCacheline()
        {
            timestamp = 0;
            signature = 0;
            valid = 0;
            tag = 0;
        }
};

#define LOG_HISTORY 8
#define HISTORY (1 << LOG_HISTORY)
#define SAMPLED_CACHEWAY HISTORY

class SamplingSet{
    public:
        SamplingCacheline sampled_cacheline[SAMPLED_CACHEWAY];
        uint64_t clock;

        uint16_t find_cache_way(uint64_t tag)
        {
            for(uint16_t i = 0; i < SAMPLED_CACHEWAY; i++){
                uint64_t cacheline_tag = sampled_cacheline[i].tag;
                bool cacheline_valid = sampled_cacheline[i].valid;
                if (cacheline_valid == true && cacheline_tag == tag){
                    return i;
                }
            }
            return SAMPLED_CACHEWAY + 1;
        }
};
SamplingSet sampled_cache[LLC_SETS];

class Cache{
    public:
        int64_t ETR[LLC_SETS][LLC_WAYS];

#if ETR_UPDATE
        int64_t ETRinit[LLC_SETS][LLC_WAYS];
        uint64_t signature[LLC_SETS][LLC_WAYS];
#if LRU
        uint64_t lru[LLC_SETS][LLC_WAYS];

        Cache(){
            for(int set = 0; set < LLC_SETS; set++){
                for(int w = 0; w < LLC_WAYS; w++)
                    lru[set][w] = 0;
            }
        }
#endif

#endif

};
Cache cache;




class pc_details{
    public:
        int64_t RDP;

#if ANALYSIS_RDP
        uint32_t count_access;
        vector<int64_t> RDlist;
        vector<int64_t> RDPerror;

#if ETR_UPDATE
        vector<int> RDPaccuracy;
        int RDPaccuracy_mean;
        vector<int> RDPaccuracy_meanlist;

        pc_details(){
            RDPaccuracy_mean = 8;
            for(int i=0; i<7; i++)
                RDPaccuracy.push_back(HISTORY);
        }
#endif

        float sum_RDPerror()
        {
            if (RDPerror.size() == 0)
                return 0;
            float total = 0;
            for (int i = 0; i < RDPerror.size(); i++)
                total = total + abs(RDPerror[i]);
            return total;
        }
        
        float mean_RDPerror()
        {
            if (RDPerror.size() == 0)
                return 0;
            float average = sum_RDPerror()/RDPerror.size();
            return average;
        }
        
        
        float mean_RD()
        {
            if (RDlist.size() == 0)
                return std::nanf("");
            
            float average = 0;
            for (int i = 0; i < RDlist.size(); i++)
                average = average + RDlist[i];
            average = average/RDlist.size();
            
            return average;
        }

        float stddev_RD()
        {
            if (RDlist.size() == 0)
                return std::nanf("");
            
            float average = mean_RD();
            float variance = 0;
            for (int i = 0; i < RDlist.size(); i++)
                variance = variance + pow((RDlist[i] - average),2);
            variance = variance/RDlist.size();
            
            float std_dev = sqrt(variance);
            return std_dev;
        }

        uint64_t RD_diff_total()
        {
            if (RDlist.size() < 2)
                return std::nanf("");

            uint64_t total = 0;
            for (int i = 1; i < RDlist.size(); i++)
                total = total + abs(RDlist[i] - RDlist[i-1]);

            return total;
        }

        float RD_diff_average()
        {
            if (RDlist.size() < 2)
                return std::nanf("");

            float average = ((float)RD_diff_total())/RDlist.size();
            
            return average;
        }

        uint32_t RD_jumps(float threshold)
        {
            if (RDlist.size() < 2)
                return std::nanf("");
            uint32_t no_of_jumps = 0;
            for (int i = 1; i < RDlist.size(); i++){
                if(abs(RDlist[i] - RDlist[i-1]) > threshold )
                    no_of_jumps++;
            }
            return no_of_jumps;
        }
#endif

};

unordered_map<uint64_t, pc_details> pc_data;


uint64_t get_pc_signature(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit);
int64_t updateRD(int64_t elapsed_time, int64_t initial_RD);



uint64_t find_cache_tag(uint64_t full_addr)
{    
    full_addr = full_addr >> (LOG2_LLC_SET + LOG2_BLOCK_SIZE);
    return full_addr;
}    

int64_t time_difference(uint64_t max_time, uint64_t min_time)
{
    return ((int64_t)max_time - (int64_t)min_time);
}

uint64_t increment_timestamp(uint64_t time)
{
    time = time + 1;
    return time;
}

#define INFINITE_RD (HISTORY-1)

void replacement_operation(uint32_t set, uint16_t way, int64_t elapsed_time){

    SamplingCacheline temp_cacheline = sampled_cache[set].sampled_cacheline[way];
    if(temp_cacheline.valid == false)
        return;

    if (pc_data.count(temp_cacheline.signature)){
        int64_t initial_RD = pc_data[temp_cacheline.signature].RDP;
        pc_data[temp_cacheline.signature].RDP = min(updateRD(elapsed_time, initial_RD), (int64_t)INFINITE_RD);
    }
    else {
        pc_data[temp_cacheline.signature].RDP = INFINITE_RD;
#if ANALYSIS_RDP
        pc_data[temp_cacheline.signature].RDlist.push_back(INFINITE_RD);
        pc_data[temp_cacheline.signature].count_access = 1;
#endif
    }
    sampled_cache[set].sampled_cacheline[way].valid = false;
} 






uint64_t previous_pc = 0x000000000;


void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t pc, uint64_t victim_addr, uint32_t type, uint8_t hit)
{

#if LRU
    if(way < LLC_WAYS){
        for(int w = 0; w < LLC_WAYS; w++){
            cache.lru[set][w]++;
        }
        cache.lru[set][way] = 0;
    } 
#endif

    uint64_t pc_signature = get_pc_signature(pc, previous_pc, type, hit);
    previous_pc = pc;

    //Not sure what this does - Is it required?? Fuck yeah - When it is writeback - don't update RDP
    if (type == WRITEBACK) {
        if(!hit) {
            cache.ETR[set][way] = -INFINITE_RD;
#if ETR_UPDATE
            cache.ETRinit[set][way] = cache.ETR[set][way];
            cache.signature[set][way] = pc_signature;   
#endif        
        }
        return;
    }


    uint64_t cache_tag = find_cache_tag(full_addr);
    uint16_t cache_way = sampled_cache[set].find_cache_way(cache_tag);

    //TODO: PC Signature can include whether it is a hit or not



    uint16_t replaceable_way = SAMPLED_CACHEWAY + 1;

    //Not found in sampled_cache
    if(cache_way >= SAMPLED_CACHEWAY){

        int64_t lru_RD = -1;
        for(uint16_t w = 0; w < SAMPLED_CACHEWAY; w++){

            if (sampled_cache[set].sampled_cacheline[w].valid == false){
                replaceable_way = w;
                goto REPLACEMENT_WAY_FOUND;
            } 

            uint64_t last_timestamp = sampled_cache[set].sampled_cacheline[w].timestamp;
            int64_t elapsed_time = time_difference(sampled_cache[set].clock, last_timestamp);
            
            if (elapsed_time >= INFINITE_RD) {
                replaceable_way = w;
                lru_RD = elapsed_time;
                break;
            }
            
            else if (elapsed_time > lru_RD) {
                replaceable_way = w;
                lru_RD = elapsed_time;
            }
        }        
        replacement_operation(set, replaceable_way, lru_RD);
    }

REPLACEMENT_WAY_FOUND:

    if(cache_way >= SAMPLED_CACHEWAY){
        sampled_cache[set].sampled_cacheline[replaceable_way].valid = true;
        sampled_cache[set].sampled_cacheline[replaceable_way].signature = pc_signature;
        sampled_cache[set].sampled_cacheline[replaceable_way].tag = cache_tag;
        sampled_cache[set].sampled_cacheline[replaceable_way].timestamp = sampled_cache[set].clock;
    }




    if(cache_way < SAMPLED_CACHEWAY ){

        uint64_t last_timestamp = sampled_cache[set].sampled_cacheline[cache_way].timestamp;
        uint64_t last_signature = sampled_cache[set].sampled_cacheline[cache_way].signature;
        int64_t elapsed_time = time_difference(sampled_cache[set].clock, last_timestamp);

//Do we have to include elapsed_time < INFINITE_RD condition here??
        if (pc_data.count(last_signature)){
            int64_t initial_RD = pc_data[last_signature].RDP;
            pc_data[last_signature].RDP = min(updateRD(elapsed_time, initial_RD),(int64_t)INFINITE_RD);

#if ANALYSIS_RDP
            pc_data[last_signature].RDPerror.push_back((elapsed_time - initial_RD));
            pc_data[last_signature].count_access += 1;
            pc_data[last_signature].RDlist.push_back(min(elapsed_time,(int64_t)INFINITE_RD));
#endif 
        }

        else {
            pc_data[last_signature].RDP = min(elapsed_time, (int64_t)INFINITE_RD);

#if ANALYSIS_RDP
            pc_data[last_signature].count_access = 1;
            pc_data[last_signature].RDlist.push_back(min(elapsed_time,(int64_t)INFINITE_RD));
#endif 

        }

        sampled_cache[set].sampled_cacheline[cache_way].timestamp = sampled_cache[set].clock;
        sampled_cache[set].sampled_cacheline[cache_way].valid = true;
        sampled_cache[set].sampled_cacheline[cache_way].signature = pc_signature;
        sampled_cache[set].sampled_cacheline[cache_way].tag = cache_tag;
    }

    sampled_cache[set].clock = increment_timestamp(sampled_cache[set].clock);



    for(uint16_t w = 0; w < LLC_WAYS; w++) {
        if(w != way && cache.ETR[set][w] > -((int64_t)INFINITE_RD)){
            cache.ETR[set][w]--;
        }
    }


#if ETR_UPDATE
    int rd_accuracy = 0;
    if(way < LLC_WAYS) {
        if(hit && type!= WRITEBACK){ 
            rd_accuracy = cache.ETR[set][way];

            pc_data[cache.signature[set][way]].RDPaccuracy.push_back(rd_accuracy);

            int size = pc_data[cache.signature[set][way]].RDPaccuracy.size();
            pc_data[cache.signature[set][way]].RDPaccuracy_mean = 0;
            for (int i = size-1; i > size-17; i--){
                pc_data[cache.signature[set][way]].RDPaccuracy_mean += pc_data[cache.signature[set][way]].RDPaccuracy[i]; 
            }
            pc_data[cache.signature[set][way]].RDPaccuracy_mean /= 16;
            pc_data[cache.signature[set][way]].RDPaccuracy_meanlist.push_back(pc_data[cache.signature[set][way]].RDPaccuracy_mean); 
        }
    }
#endif

    if(way < LLC_WAYS) {
        if(pc_data.count(pc_signature)){
            cache.ETR[set][way] = pc_data[pc_signature].RDP;
        }
        else{
            //TODO: Check out whether this affects 
            cache.ETR[set][way] = 0;
        }
    }

#if ETR_UPDATE
    if(way < LLC_WAYS) {    
        cache.ETRinit[set][way] = cache.ETR[set][way];
        cache.signature[set][way] = pc_signature;
    }   
#endif

}



#if ETR_UPDATE
    fstream ETRfile("ETR.txt", ios::out);
#endif

uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK *current_set, uint64_t pc, uint64_t full_addr, uint32_t type)
{
    /* don't modify this code or put anything above it;
     * if there's an invalid block, we don't need to evict any valid ones */
#if ANALYSIS_ETA
    cout << endl << "Set : " << set << "\t ETA: "; 
    for (int way = 0; way < LLC_WAYS; way++) {
        cout << " " << cache.ETR[set][way] << " "; 
    }
#endif


#if ETR_UPDATE
//    ETRfile << endl << "Set:" << "\t" << set << "\t" <<"ETA: "; 
//    for (int way = 0; way < LLC_WAYS; way++) {
//        ETRfile << "\t" << cache.ETR[set][way];
//        if (pc_data.count(cache.signature[set][way])){
//            int temp = pc_data[cache.signature[set][way]].RDPaccuracy_mean;
//            ETRfile <<"(" << temp <<")";
//        } 
//    }
#endif

    for (int way = 0; way < LLC_WAYS; way++) {
        if (current_set[way].valid == false) {
#if ANALYSIS_ETA
            cout << "\t\t victim: " << way; 
#endif
#if ETR_UPDATE
//            ETRfile << "\t" <<"victim:" << "\t"<< way; 
#endif
            return way;
        }
    }

    int64_t etr[LLC_WAYS];
    for (int way = 0; way < LLC_WAYS; way++) {
        etr[way] = cache.ETR[set][way];
    }


    uint16_t victim_way = 0;

#if LRU 

    int64_t max_etr = 0;
    uint16_t max_etr_way = 0;

    for (int way = 0; way < LLC_WAYS; way++) {
        if (abs(etr[way]) > max_etr || (abs(etr[way]) == max_etr && etr[way] < 0)) {
            max_etr = abs(etr[way]);
            max_etr_way = way;
        }
    }

    if (pc_data.count(cache.signature[set][max_etr_way])){

        int variation = pc_data[cache.signature[set][max_etr_way]].RDPaccuracy_mean;

        bool ways_within_variance[LLC_WAYS];
        for (int way = 0; way < LLC_WAYS; way++){
            ways_within_variance[way] = 0;
            if(abs(abs(etr[max_etr_way]) - abs(etr[way])) <= abs(variation)){
                ways_within_variance[way] = 1;
            }
            ways_within_variance[max_etr_way] = 1;
        }
        
        uint64_t max_lru = cache.lru[set][max_etr_way]; 
        uint16_t max_lru_etr_way = max_etr_way;

        for (int way = 0; way < LLC_WAYS; way++) {
            if(ways_within_variance[way] == 1 && cache.lru[set][way] >= max_lru){
                max_lru_etr_way = way;
                max_lru = cache.lru[set][way];
            }
        }
        victim_way = max_lru_etr_way;
    }
    else{
        victim_way = max_etr_way;
    }
#else
    int64_t max_etr = 0;

    for (int way = 0; way < LLC_WAYS; way++) {
        if (abs(etr[way]) > max_etr || (abs(etr[way]) == max_etr && etr[way] < 0)) {
            max_etr = abs(etr[way]);
            victim_way = way;
        }
    }
#endif


#if ANALYSIS_ETA
    cout << "\t\t victim: " << victim_way; 
#endif
#if ETR_UPDATE
//            ETRfile << "\t" <<"victim:" << "\t"<< victim_way; 
#endif


    return victim_way;

}






void CACHE::replacement_final_stats()
{

#if ANALYSIS_RDP    

    unordered_map<uint64_t, pc_details>::iterator pc_itr;




    unordered_map<uint32_t, uint64_t>pc_count_access;
    unordered_map<uint32_t, uint64_t>::iterator itr_count;
    for (pc_itr = pc_data.begin(); pc_itr != pc_data.end(); pc_itr++)
    {
        if(!pc_count_access.count(pc_itr->second.count_access))
            pc_count_access[pc_itr->second.count_access] = 1;
        else
            pc_count_access[pc_itr->second.count_access] += 1;
    }
    // cout << endl;
    cout << endl << endl << "PC Number : " << pc_data.size() << endl << endl;

    for (itr_count = pc_count_access.begin(); itr_count != pc_count_access.end(); itr_count++)
    {
        // cout << itr_count->first<<" "<<itr_count->second << endl;
    }




    uint64_t sum_diff_RD = 0;
    float sum_RDPerror = 0;
    for (pc_itr = pc_data.begin(); pc_itr != pc_data.end(); pc_itr++)
    {
        // cout << endl << pc_itr->first << "\t";

        // for (int i = 0; i < pc_itr->second.RDPaccuracy.size(); i++)
        //     cout << pc_itr->second.RDPaccuracy[i] << "  ";

        // for (int i = 0; i < pc_itr->second.RDlist.size(); i++)
        //     cout << pc_itr->second.RDlist[i] << "  ";
        // cout << pc_itr->second.mean_RD() << "\t";
        // cout << pc_itr->second.stddev_RD() << "\t";
        
        // cout << pc_itr->second.RD_diff_average() << "\t";
        // cout << pc_itr->second.RD_jumps(pc_itr->second.stddev_RD())<< "\t";
        // cout << pc_itr->second.RD_jumps(pc_itr->second.stddev_RD()/2)<< "\t";
        // cout << pc_itr->second.RDlist.size() << "\t";
        
        // cout << pc_itr->second.count_access << "\t";
        
        // cout << pc_itr->second.sum_RDPerror() << "\t";
        // cout << pc_itr->second.mean_RDPerror() << "\t";
        
        sum_diff_RD = sum_diff_RD + pc_itr->second.RD_diff_total();
        sum_RDPerror = sum_RDPerror + pc_itr->second.sum_RDPerror();
    }

    cout << endl << endl << "Total Difference RDP Error : " << sum_RDPerror << endl << endl;

//   fstream pc_RDfile("pc_RDfile.txt", ios::out);
//    for (pc_itr = pc_data.begin(); pc_itr != pc_data.end(); pc_itr++)
//    {
//        pc_RDfile << endl << pc_itr->first << " ";
//        for (int i = 0; i < pc_itr->second.RDlist.size(); i++)
//            pc_RDfile << pc_itr->second.RDlist[i] << " ";
//    }
//    pc_RDfile.close();



#if ETR_UPDATE
//    fstream RDaccuracyfile("pc_RDaccuracy.txt", ios::out);
//    for (pc_itr = pc_data.begin(); pc_itr != pc_data.end(); pc_itr++)
//    {
//        RDaccuracyfile << endl << pc_itr->first << " ";
//        for (int i = 0; i < pc_itr->second.RDPaccuracy_meanlist.size(); i++) {
//            RDaccuracyfile << pc_itr->second.RDPaccuracy_meanlist[i] << " ";
//        }
//    }
//    RDaccuracyfile.close();
#endif


#if ETR_UPDATE
    ETRfile.close();
#endif

#endif

}







void CACHE::initialize_replacement()
{
    for(int i=0; i < LLC_SETS; i++)
        sampled_cache[i].clock = 0;
}





uint64_t get_pc_signature1(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit);
uint64_t get_pc_signature2(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit);
uint64_t get_pc_signature3(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit);
uint64_t get_pc_signature4(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit);
uint64_t get_pc_signature5(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit);


uint64_t get_pc_signature(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit)
{
    return get_pc_signature5(pc, previous_pc, type, hit);
}


static const unsigned int crc32_table[] =
{
  0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
  0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
  0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
  0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
  0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
  0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
  0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
  0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
  0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
  0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
  0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
  0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
  0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
  0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
  0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
  0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
  0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
  0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
  0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
  0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
  0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
  0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
  0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
  0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
  0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
  0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
  0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
  0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
  0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
  0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
  0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
  0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
  0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
  0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
  0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
  0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
  0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
  0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
  0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
  0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
  0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
  0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
  0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

uint64_t xcrc32 (uint64_t pc)
{
    uint32_t crc = 0xf464a0aa;
    uint8_t len = 0;
    while (len < 8){
        uint8_t buf = (pc >> len * 8) & 0xff;
        crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ buf) & 255];
        len++;
    }
    return crc;
}

uint64_t get_pc_signature1(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit)
{
    return xcrc32(pc);
}

uint64_t get_pc_signature2(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit)
{
    uint64_t pc_hash = (xcrc32(previous_pc) << 32) | (xcrc32(pc));
    return pc_hash;
}

uint64_t get_pc_signature3(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit)
{
    uint64_t pc_attributes = ((uint64_t)type << 32) | ((uint64_t)hit);
    uint64_t pc_hash = (xcrc32(pc_attributes) << 32) | (xcrc32(pc));
    return pc_hash;
}

uint64_t get_pc_signature4(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit)
{
    uint64_t pc_attributes = (uint64_t)type;
    uint64_t pc_hash = (xcrc32(pc_attributes) << 32) | (xcrc32(pc));
    return pc_hash;
}

uint64_t get_pc_signature5(uint64_t pc, uint64_t previous_pc, uint32_t type, uint8_t hit)
{
    uint64_t pc_attributes = (uint64_t)hit;
    uint64_t pc_hash = (xcrc32(pc_attributes) << 32) | (xcrc32(pc));
    return pc_hash;
}


int64_t updateRD1(int64_t elapsed_time, int64_t initial_RD); //returns elapsed_time
int64_t updateRD2(int64_t elapsed_time, int64_t initial_RD, float time_difference); //Considers a difference
int64_t updateRD3(int64_t elapsed_time, int64_t initial_RD, float time_difference); //Considers a difference


int64_t updateRD(int64_t elapsed_time, int64_t initial_RD)
{
    float time_difference = 1/8;
    // return updateRD1(elapsed_time, initial_RD);
    return updateRD2(elapsed_time, initial_RD, time_difference);
}

int64_t updateRD1(int64_t elapsed_time, int64_t initial_RD)
{
    return elapsed_time;
}

int64_t updateRD2(int64_t elapsed_time, int64_t initial_RD, float time_difference)
{
    if (elapsed_time > initial_RD) {
        int64_t diff = elapsed_time - initial_RD;
        diff = (int64_t)((float)diff * time_difference);
        diff = min((int64_t)1, diff);
        return min(initial_RD + diff, (int64_t)INFINITE_RD);
    }      
    else if (elapsed_time < initial_RD) {
        int64_t diff = initial_RD - elapsed_time;
        diff = (int64_t)((float)diff * time_difference);
        diff = min((int64_t)1, diff);
        return max(initial_RD - diff, (int64_t)0);
    }      
    else {
        return initial_RD;
    }
}

int64_t updateRD3(int64_t elapsed_time, int64_t initial_RD, float time_difference)
{
    if (elapsed_time > initial_RD) {
        int64_t diff = elapsed_time - initial_RD;
        diff = (int64_t)((float)diff * time_difference);
        return min(initial_RD + diff, (int64_t)INFINITE_RD);
    }      
    else if (elapsed_time < initial_RD) {
        int64_t diff = initial_RD - elapsed_time;
        diff = (int64_t)((float)diff * time_difference);
        return max(initial_RD - diff, (int64_t)0);
    }      
    else {
        return initial_RD;
    }
}


