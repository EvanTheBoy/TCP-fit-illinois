#include <algorithm>   
#include "TCPIllinois.h"
#include "TCP.h"

#define ALPHA_SHIFT     7
#define ALPHA_SCALE     (1u << ALPHA_SHIFT)
#define ALPHA_MIN       ((3 * ALPHA_SCALE) / 10 ) /* ~0.3 */
#define ALPHA_MAX       ( 10 * ALPHA_SCALE ) /* 10.0 */
#define ALPHA_BASE      ALPHA_SCALE /* 1.0 */
#define RTT_MAX         (UINT32_MAX / ALPHA_MAX) /* 3.3 secs */

#define BETA_SHIFT      6
#define BETA_SCALE      (1u << BETA_SHIFT)
#define BETA_MIN        (BETA_SCALE / 8) /* 0.125 */
#define BETA_MAX        (BETA_SCALE / 2) /* 0.5 */
#define BETA_BASE       BETA_MAX

static int theta = 5;

Register_Class(TCPIllinois);

TCPIllinoisStateVariables::TCPIllinoisStateVariables() {
 
    ssthresh = 0xffffffff; 
    snd_cwnd_clamp = UINT32_MAX; 
    snd_cwnd = 2;
    snd_cwnd_cnt = 0;
    acked = 0;
    base_rtt = 0x7fffffff;
    cnt_rtt = 0;
    max_rtt = 0;
    rtt_low = 0;
    rtt_above = 0;
    beta = BETA_BASE;
    alpha = ALPHA_MAX;
    sum_rtt = 0;
    end_seq = 0;
}

TCPIllinoisStateVariables::~TCPIllinoisStateVariables() {
}

std::string TCPIllinoisStateVariables::info() const {
    std::stringstream out;
    out << TCPBaseAlgStateVariables::info();
    out << " ssthresh=" << ssthresh;
    return out.str();
}

std::string TCPIllinoisStateVariables::detailedInfo() const {
    std::stringstream out;
    out << TCPBaseAlgStateVariables::detailedInfo();
    out << "ssthresh = " << ssthresh << "\n";
    out << "minRTT = " << base_rtt << "\n";
    return out.str();
}


TCPIllinois::TCPIllinois() :
    TCPBaseAlg(), state((TCPIllinoisStateVariables*&)TCPAlgorithm::state) {
}

void TCPIllinois::recalculateSlowStartThreshold() { 
    EV_DEBUG << "recalculateSlowStartThreshold(), ssthresh=" << state->ssthresh
        << "\n";

    
    state->ssthresh = std::max((state->snd_cwnd * state->beta) >> BETA_SHIFT,
        2U);

    if (ssthreshVector) {
        ssthreshVector->record(state->ssthresh);
    }
}

void TCPIllinois::processRexmitTimer(TCPEventCode& event) {
    TCPBaseAlg::processRexmitTimer(event);
    if (event == TCP_E_ABORT)
        return;

    state->recover = (state->snd_max - 1);
    EV_INFO << "recover=" << state->recover << "\n";
    state->lossRecovery = false;
    state->firstPartialACK = false;
    EV_INFO << "Loss Recovery terminated.\n";

    
    recalculateSlowStartThreshold();
    state->snd_cwnd = state->snd_mss;

    if (cwndVector) {
        cwndVector->record(state->snd_cwnd);
    }

    EV_INFO << "Begin Slow Start: resetting cwnd to " << state->snd_cwnd
        << ", ssthresh=" << state->ssthresh << "\n";
    state->afterRto = true;
    conn->retransmitOneSegment(true);
}

void TCPIllinois::receivedDataAck(uint32 firstSeqAcked) {
    TCPBaseAlg::receivedDataAck(firstSeqAcked);
    const TCPSegmentTransmitInfoList::Item* found = state->regions.get(
        firstSeqAcked);

    if (found != nullptr) { 
        simtime_t currentTime = simTime();
        simtime_t newRTT = currentTime - found->getFirstSentTime();

        
        if (newRTT > RTT_MAX) {
            newRTT = RTT_MAX;
        }

        
        if (state->base_rtt > newRTT) {
            state->base_rtt = newRTT;
        }
        
        if (state->max_rtt < newRTT) {
            state->max_rtt = newRTT;
        }
        ++state->cnt_rtt;
        state->sum_rtt += newRTT.dbl();
    }

    state->regions.clearTo(state->snd_una);

    
    if (state->lossRecovery) {
        if (seqGE(state->snd_una - 1, state->recover)) {
            uint32 flight_size = state->snd_max - state->snd_una;
            state->snd_cwnd = std::min(state->ssthresh,
                flight_size + state->snd_mss);
            EV_INFO
                << "Fast Recovery - Full ACK received: Exit Fast Recovery, setting cwnd to "
                << state->snd_cwnd << "\n";
            if (cwndVector)
                cwndVector->record(state->snd_cwnd);

            
            state->lossRecovery = false;
            state->firstPartialACK = false;
            EV_INFO << "Loss Recovery terminated.\n";
        }
        else {
            EV_INFO
                << "Fast Recovery - Partial ACK received: retransmitting the first unacknowledged segment\n";
            
            conn->retransmitOneSegment(false);

            
            state->snd_cwnd -= state->snd_una - firstSeqAcked;

            if (cwndVector)
                cwndVector->record(state->snd_cwnd);

            EV_INFO
                << "Fast Recovery: deflating cwnd by amount of new data acknowledged, new cwnd="
                << state->snd_cwnd << "\n";

            
            if (state->snd_una - firstSeqAcked >= state->snd_mss) {
                state->snd_cwnd += state->snd_mss;

                if (cwndVector)
                    cwndVector->record(state->snd_cwnd);

                EV_DETAIL << "Fast Recovery: inflating cwnd by SMSS, new cwnd="
                    << state->snd_cwnd << "\n";
            }

            
            sendData(false);

            
            if (state->lossRecovery) {
                if (!state->firstPartialACK) {
                    state->firstPartialACK = true;
                    EV_DETAIL
                        << "First partial ACK arrived during recovery, restarting REXMIT timer.\n";
                    restartRexmitTimer();
                }
            }
        }
    }
    else {
       
        if (seqGreater(state->snd_una, state->end_seq)) {
            update_params(state);
        }
       form slow start (TCP NewReno) and congestion avoidance.
        
        if (state->snd_cwnd <= state->ssthresh) {
            EV_DETAIL
                << "cwnd <= ssthresh: Slow Start: increasing cwnd by SMSS bytes to ";

            state->snd_cwnd += state->snd_mss;
            if (cwndVector) {
                cwndVector->record(state->snd_cwnd);
            }

            EV_DETAIL << "cwnd=" << state->snd_cwnd << "\n";
        }
        else {
            uint32_t delta;
            if (state->acked == 0) {
                state->acked = 1;
            }

            state->snd_cwnd_cnt += state->acked; 
            state->acked = 1;
          
            delta = (state->snd_cwnd_cnt * state->alpha) >> ALPHA_SHIFT;
            if (delta >= state->snd_cwnd) {
                state->snd_cwnd = std::min(
                    (state->snd_cwnd + delta) / state->snd_cwnd,
                    state->snd_cwnd_clamp);
                state->snd_cwnd_cnt = 0;
            }

            if (cwndVector) {
                cwndVector->record(state->snd_cwnd);
            }
            EV_DETAIL
                << "TCP Illinois cwnd > ssthresh: Congestion Avoidance: increasing cwnd, to "
                << state->snd_cwnd << "\n";
        }
        state->recover = (state->snd_una - 2);
    }
    sendData(false);
}

void TCPIllinois::receivedDuplicateAck() {
    TCPBaseAlg::receivedDuplicateAck();

    if (state->dupacks == DUPTHRESH) {   
        if (!state->lossRecovery) {
           
            if (state->snd_una - 1 > state->recover) {
               
                reset_state(state);

                EV_INFO
                    << "TCP Illinois on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";

               
                recalculateSlowStartThreshold();
                state->recover = (state->snd_max - 1);
                state->firstPartialACK = false;
                state->lossRecovery = true;
                EV_INFO << " set recover=" << state->recover;

               
                state->snd_cwnd = state->ssthresh + 3 * state->snd_mss;

                if (cwndVector) {
                    cwndVector->record(state->snd_cwnd);
                }

                EV_DETAIL << " , cwnd=" << state->snd_cwnd << ", ssthresh="
                    << state->ssthresh << "\n";
                conn->retransmitOneSegment(false);

               
                sendData(false);
            }
            else {
                EV_INFO
                    << "TCP Illinois on dupAcks == DUPTHRESH(=3): not invoking Fast Retransmit and Fast Recovery\n";
               
            }
        }
        EV_INFO
            << "TCP Illinois on dupAcks == DUPTHRESH(=3): TCP is already in Fast Recovery procedure\n";
    }
    else if (state->dupacks > DUPTHRESH) {    
        if (state->lossRecovery) {
           
            state->snd_cwnd += state->snd_mss;

            if (cwndVector)
                cwndVector->record(state->snd_cwnd);

            EV_DETAIL
                << "TCP Illinois on dupAcks > DUPTHRESH(=3): Fast Recovery: inflating cwnd by SMSS, new cwnd="
                << state->snd_cwnd << "\n";

           
            sendData(false);
        }
    }
}

void TCPIllinois::dataSent(uint32 fromseq) {
    TCPBaseAlg::dataSent(fromseq);

   

    simtime_t sendtime = simTime();
    state->regions.clearTo(state->snd_una);
    state->regions.set(fromseq, state->snd_max, sendtime);
}

void TCPIllinois::segmentRetransmitted(uint32 fromseq, uint32 toseq) {
    TCPBaseAlg::segmentRetransmitted(fromseq, toseq);

    state->regions.clearTo(state->snd_una);
    state->regions.set(fromseq, toseq, simTime());
}


void TCPIllinois::reset_state(TCPIllinoisStateVariables*& state) {
    state->alpha = ALPHA_BASE;
    state->beta = BETA_BASE;
    state->rtt_low = 0;
    state->rtt_above = 0;
    rtt_reset(state);
}


void TCPIllinois::update_params(TCPIllinoisStateVariables*& state) {
    if (state->snd_cwnd < state->ssthresh) {
        state->alpha = ALPHA_BASE;
        state->beta = BETA_BASE;
    }
    else if (state->cnt_rtt > 0) {
        
        double dm = state->max_rtt.dbl() - state->base_rtt.dbl(); 
               
        double da = (state->sum_rtt / state->cnt_rtt) - state->base_rtt.dbl();
        state->alpha = alpha(state, da, dm);
        state->beta = beta(da, dm);
    }
    rtt_reset(state);
}

void TCPIllinois::rtt_reset(TCPIllinoisStateVariables*& state) {
    state->end_seq = state->snd_nxt;
    state->cnt_rtt = 0;
    state->sum_rtt = 0;
}


uint32_t TCPIllinois::alpha(TCPIllinoisStateVariables*& state, double da,
    double dm) {
    double d1 = dm / 100;

    if (da <= d1) {
       
        if (!state->rtt_above) {
            return ALPHA_MAX;
        }
        
        if (++state->rtt_low < theta) {
            return state->alpha;
        }

        state->rtt_low = 0;
        state->rtt_above = 0;

        return ALPHA_MAX;
    }

    state->rtt_above = 1;

   
    dm -= d1;
    da -= d1;
    return (dm * ALPHA_MAX) / (dm + (da * (ALPHA_MAX - ALPHA_MIN)) / ALPHA_MIN);
}


uint32_t TCPIllinois::beta(double da, double dm) {
    double d2, d3;
    d2 = dm / 10;

    if (da <= d2) {
        return BETA_MIN;
    }

    d3 = (8 * dm) / 10;

    if (da >= d3 || d3 <= d2) {
        return BETA_MAX;
    }

   
    return (BETA_MIN * d3 - BETA_MAX * d2 + (BETA_MAX - BETA_MIN) * da)
        / (d3 - d2);
}
