#include <algorithm>    
#include "TCPFit.h"
#include "TCP.h"

#define BETA_VALUE  0
#define UPD_INTERVAL 0.500

Register_Class(TCPFit);

TCPFitStateVariables::TCPFitStateVariables() {
    update_epoch = 0;
    ssthresh = 0xffffffff;
    snd_cwnd = 2;
    w_RTTmin = 0x7fffffff;
    w_RTTmax = 0;
    RTT_cnt = 0;
    ACK_cnt = 0;
    epoch_start = 0;
    cwnd_cnt = 0;
    upd_interval = (simtime_t)UPD_INTERVAL;
    nValue = 1;
    beta = BETA_VALUE;
    alpha = 1;

}

TCPFitStateVariables::~TCPFitStateVariables() {
}

std::string TCPFitStateVariables::info() const {
    std::stringstream out;
    out << TCPBaseAlgStateVariables::info();
    out << " ssthresh=" << ssthresh;
    return out.str();
}

std::string TCPFitStateVariables::detailedInfo() const {
    std::stringstream out;
    out << TCPBaseAlgStateVariables::detailedInfo();
    out << "ssthresh = " << ssthresh << "\n";
    out << "w_RTTmin = " << w_RTTmin << "\n";
    return out.str();
}


TCPFit::TCPFit() :
    TCPBaseAlg(), state((TCPFitStateVariables*&)TCPAlgorithm::state) {
}


TCPFit::~TCPFit() {
    delete nValueVector;
}

void TCPFit::recalculateSlowStartThreshold() {
    EV_DEBUG << "recalculateSlowStartThreshold(), ssthresh=" << state->ssthresh
        << "\n";
    state->ssthresh = state->snd_cwnd
        - (state->snd_cwnd * (2 / ((3 * state->nValue) + 1)));

    if (ssthreshVector) {
        ssthreshVector->record(state->ssthresh);
    }
}

void TCPFit::processRexmitTimer(TCPEventCode& event) {
    TCPBaseAlg::processRexmitTimer(event);

    if (event == TCP_E_ABORT) {
        return;
    }

    recalculateSlowStartThreshold();
    state->snd_cwnd = state->snd_mss;

    if (cwndVector)
        cwndVector->record(state->snd_cwnd);

    state->afterRto = true;
    conn->retransmitOneSegment(true);
}

void TCPFit::receivedDataAck(uint32 firstSeqAcked) {
    TCPBaseAlg::receivedDataAck(firstSeqAcked);
    const TCPSegmentTransmitInfoList::Item* found = state->regions.get(
        firstSeqAcked);

    if (found != nullptr) {
        simtime_t currentTime = simTime();
        simtime_t newRTT = currentTime - found->getFirstSentTime();

        state->RTT_cnt += newRTT;


        state->w_RTTmin = std::min(state->w_RTTmin, newRTT);

        state->w_RTTmax = std::max(state->w_RTTmin, newRTT);

        state->update_epoch = std::max(newRTT, state->upd_interval);
    }
    state->regions.clearTo(state->snd_una);

    if (state->dupacks >= DUPTHRESH) {
        EV_INFO << "Fast Recovery: setting cwnd to ssthresh=" << state->ssthresh
            << "\n";
        state->snd_cwnd = state->ssthresh;

        if (cwndVector)
            cwndVector->record(state->snd_cwnd);
    }
    else {
        state->ACK_cnt++;

        if (state->snd_cwnd <= state->ssthresh) {

            state->snd_cwnd++;

            if (cwndVector) {
                cwndVector->record(state->snd_cwnd);
            }

            EV_INFO << "cwnd=" << state->snd_cwnd << "\n";
        }
        else {

            state->cwnd_cnt += state->nValue;

            if (state->cwnd_cnt > state->snd_cwnd) {
                state->snd_cwnd++;
            }
        }

        if (cwndVector)
            cwndVector->record(state->snd_cwnd);
    }

    TCPFit::tcpFitUpdateN();
    state->regions.clearTo(state->snd_una);

    sendData(false);
}

void TCPFit::receivedDuplicateAck() {
    TCPBaseAlg::receivedDuplicateAck();
    if (state->dupacks == DUPTHRESH) {
        EV_INFO
            << "Reno on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";

        if (state->sack_enabled) {
            // RFC 3517, page 6 and page 8
            if (state->recoveryPoint == 0
                || seqGE(state->snd_una, state->recoveryPoint)) {
                state->recoveryPoint = state->snd_max;
                state->lossRecovery = true;
                EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;
            }
        }

        recalculateSlowStartThreshold();

        state->snd_cwnd = 2;
        tcpFitReset();

        if (cwndVector) {
            cwndVector->record(state->snd_cwnd);
        }

        EV_DETAIL << " set cwnd=" << state->snd_cwnd << ", ssthresh="
            << state->ssthresh << "\n";

        conn->retransmitOneSegment(false);

        if (state->sack_enabled) {

            conn->setPipe();

            if (state->lossRecovery) {

                EV_INFO
                    << "Retransmission sent during recovery, restarting REXMIT timer.\n";
                restartRexmitTimer();

                if (((int)state->snd_cwnd - (int)state->pipe)
                    >= (int)state->snd_mss) {
                    conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
                }
            }
        }


        sendData(false);
    }
    else if (state->dupacks > DUPTHRESH) {

        state->snd_cwnd += state->snd_mss;
        EV_DETAIL
            << "Reno on dupAcks > DUPTHRESH(=3): Fast Recovery: inflating cwnd by SMSS, new cwnd="
            << state->snd_cwnd << "\n";

        if (cwndVector) {
            cwndVector->record(state->snd_cwnd);
        }

        sendData(false);
    }
}

void TCPFit::dataSent(uint32 fromseq) {
    TCPBaseAlg::dataSent(fromseq);



    simtime_t sendtime = simTime();
    state->regions.clearTo(state->snd_una);
    state->regions.set(fromseq, state->snd_max, sendtime);
}

void TCPFit::segmentRetransmitted(uint32 fromseq, uint32 toseq) {
    TCPBaseAlg::segmentRetransmitted(fromseq, toseq);

    state->regions.clearTo(state->snd_una);
    state->regions.set(fromseq, toseq, simTime());
}

void TCPFit::tcpFitUpdateN() {
    currentTime = simTime();
    if (state->beta == 0) {
        if ((currentTime - state->epoch_start) > state->update_epoch) {
            state->epoch_start = currentTime;

            state->avgRTT = state->RTT_cnt / state->ACK_cnt;
            double rtt_diff = state->avgRTT.dbl() - state->w_RTTmin.dbl();
            double nValueTemp = state->nValue * rtt_diff;
            nValueTemp /= (state->alpha * state->avgRTT.dbl());
            state->nValue = std::max(1.0, nValueTemp);
        }
    }
    else {
        if ((currentTime - state->epoch_start) > state->update_epoch) {
            state->epoch_start = currentTime;

            double rtt_diff = state->w_RTTmax.dbl() - state->w_RTTmin.dbl();
            double nValueTemp = state->beta * rtt_diff;
            nValueTemp /= (state->alpha * state->w_RTTmax.dbl());
            nValueTemp *= state->nValue;
            nValueTemp = state->beta - nValueTemp;
            nValueTemp = state->nValue + nValueTemp;
            state->nValue = std::max(1.0, nValueTemp);
        }
    }
    if (nValueVector) {
        nValueVector->record(state->nValue);
    }

    state->RTT_cnt = 0;
    state->ACK_cnt = 0;
}

void TCPFit::tcpFitReset() {
    state->w_RTTmin = 0;
    state->RTT_cnt = 0;
    state->ACK_cnt = 0;
    currentTime = simTime();
    state->epoch_start = currentTime;
    state->cwnd_cnt = 0;
    state->nValue = 1;
    state->beta = BETA_VALUE;
    state->alpha = 1;
    state->upd_interval = (simtime_t)UPD_INTERVAL;
}