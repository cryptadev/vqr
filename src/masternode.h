// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2023-2025 Uladzimir (t.me/vovanchik_net)
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MASTERNODE_H
#define MASTERNODE_H

#include <key.h>
#include <validation.h>
#include <timedata.h>
#include <net.h>

#include <chainparams.h>
#include <primitives/transaction.h>

#include <netaddress.h>
#include <serialize.h>
#include <sync.h>

#include <validationinterface.h>

#include <chain.h>

class CMasternode;
class CMasternodeBroadcast;
class CConnman;

static const int MASTERNODE_CHECK_SECONDS               =       30;
static const int MASTERNODE_MIN_MNB_SECONDS             =   5 * 60;
static const int MASTERNODE_MIN_MNP_SECONDS             =  10 * 60;
static const int MASTERNODE_SENTINEL_PING_MAX_SECONDS   =  60 * 60;
static const int MASTERNODE_EXPIRATION_SECONDS          = 120 * 60;
static const int MASTERNODE_NEW_START_REQUIRED_SECONDS  = 180 * 60;

static const int MASTERNODE_POSE_BAN_MAX_SCORE          = 5;

//
// The Masternode Ping Class : Contains a different serialize method for sending pings from masternodes throughout the network
//

// sentinel version before implementation of nSentinelVersion in CMasternodePing
#define DEFAULT_SENTINEL_VERSION 0x010001
// daemon version before implementation of nDaemonVersion in CMasternodePing
#define DEFAULT_DAEMON_VERSION 120200

class CMasternodePing {
public:
    COutPoint masternodeOutpoint{};
    uint256 blockHash{};
    int64_t sigTime{}; //mnb message times
    std::vector<unsigned char> vchSig{};
    bool fSentinelIsCurrent = false; // true if last sentinel ping was current
    // MSB is always 0, other 3 bits corresponds to x.x.x version scheme
    uint32_t nSentinelVersion{DEFAULT_SENTINEL_VERSION};
    uint32_t nDaemonVersion{DEFAULT_DAEMON_VERSION};

    CMasternodePing() = default;

    CMasternodePing(const COutPoint& outpoint);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(masternodeOutpoint);
        READWRITE(blockHash);
        READWRITE(sigTime);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
        if(ser_action.ForRead() && s.size() == 0) {
            // TODO: drop this after migration to 70209
            fSentinelIsCurrent = false;
            nSentinelVersion = DEFAULT_SENTINEL_VERSION;
            nDaemonVersion = DEFAULT_DAEMON_VERSION;
            return;
        }
        READWRITE(fSentinelIsCurrent);
        READWRITE(nSentinelVersion);
        if(ser_action.ForRead() && s.size() == 0) {
            // TODO: drop this after migration to 70209
            nDaemonVersion = DEFAULT_DAEMON_VERSION;
            return;
        }
        READWRITE(nDaemonVersion);
    }

    uint256 GetHash() const;

    bool IsExpired() const { return GetAdjustedTime() - sigTime > MASTERNODE_NEW_START_REQUIRED_SECONDS; }

    bool Sign(const CKey& keyMasternode, const CPubKey& pubKeyMasternode);
    bool CheckSignature(const CPubKey& pubKeyMasternode, int &nDos) const;
    bool SimpleCheck(int& nDos);
    bool CheckAndUpdate(CMasternode* pmn, bool fFromNewBroadcast, int& nDos, CConnman& connman);
    void Relay(CConnman& connman);

    explicit operator bool() const;
};

inline bool operator==(const CMasternodePing& a, const CMasternodePing& b) {
    return a.masternodeOutpoint == b.masternodeOutpoint && a.blockHash == b.blockHash;
}

inline bool operator!=(const CMasternodePing& a, const CMasternodePing& b) {
    return !(a == b);
}

inline CMasternodePing::operator bool() const {
    return *this != CMasternodePing();
}

struct CMasternodeBase {
    // Note: all these constructors can be removed once C++14 is enabled.
    // (in C++11 the member initializers wrongly disqualify this as an aggregate)
    CMasternodeBase() = default;
    CMasternodeBase(CMasternodeBase const&) = default;

    CMasternodeBase(int activeState, int protoVer, int64_t sTime) :
        nActiveState{activeState}, nProtocolVersion{protoVer}, sigTime{sTime} {}

    CMasternodeBase(int activeState, int protoVer, int64_t sTime, COutPoint const& outpnt, CService const& addr,
                CPubKey const& pkCollAddr, CPubKey const& pkMN) :
        nActiveState{activeState}, nProtocolVersion{protoVer}, sigTime{sTime}, outpoint{outpnt}, addr{addr},
        pubKeyCollateralAddress{pkCollAddr}, pubKeyMasternode{pkMN} {}

    int nActiveState = 0;
    int nProtocolVersion = 0;
    int64_t sigTime = 0; //mnb message time

    COutPoint outpoint{};
    CService addr{};
    CPubKey pubKeyCollateralAddress{};
    CPubKey pubKeyMasternode{};

    int64_t nLastDsq = 0; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked = 0;
    int64_t nTimeLastPaid = 0;
    int64_t nTimeLastPing = 0; //* not in CMN
    bool fInfoValid = false; //* not in CMN
};

//
// The Masternode Class. For managing the Darksend process. It contains the input of the 1000DRK, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CMasternode : public CMasternodeBase {
private:
    mutable CCriticalSection cs;

public:
    enum state {
        MASTERNODE_PRE_ENABLED,
        MASTERNODE_ENABLED,
        MASTERNODE_EXPIRED,
        MASTERNODE_OUTPOINT_SPENT,
        MASTERNODE_UPDATE_REQUIRED,
        MASTERNODE_SENTINEL_PING_EXPIRED,
        MASTERNODE_NEW_START_REQUIRED,
        MASTERNODE_POSE_BAN
    };

    enum CollateralStatus {
        COLLATERAL_OK,
        COLLATERAL_UTXO_NOT_FOUND,
        COLLATERAL_INVALID_AMOUNT,
        COLLATERAL_INVALID_PUBKEY
    };


    CMasternodePing lastPing{};
    std::vector<unsigned char> vchSig{};

    uint256 nCollateralMinConfBlockHash{};
    int nBlockLastPaid{};
    int nPoSeBanScore{};
    int nPoSeBanHeight{};
    bool fAllowMixingTx{};
    bool fUnitTest = false;

    CMasternode();
    CMasternode(const CMasternode& other);
    CMasternode(const CMasternodeBroadcast& mnb);
    CMasternode(CService addrNew, COutPoint outpointNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyMasternodeNew, int nProtocolVersionIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        READWRITE(outpoint);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyMasternode);
        READWRITE(lastPing);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nLastDsq);
        READWRITE(nTimeLastChecked);
        READWRITE(nTimeLastPaid);
        READWRITE(nActiveState);
        READWRITE(nCollateralMinConfBlockHash);
        READWRITE(nBlockLastPaid);
        READWRITE(nProtocolVersion);
        READWRITE(nPoSeBanScore);
        READWRITE(nPoSeBanHeight);
        READWRITE(fAllowMixingTx);
        READWRITE(fUnitTest);
    }

    // CALCULATE A RANK AGAINST OF GIVEN BLOCK
    arith_uint256 CalculateScore(const uint256& blockHash) const;

    bool UpdateFromNewBroadcast(CMasternodeBroadcast& mnb, CConnman& connman);

    static CollateralStatus CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey);
    static CollateralStatus CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey, int& nHeightRet);
    void Check(bool fForce = false);

    bool IsBroadcastedWithin(int nSeconds) { return GetAdjustedTime() - sigTime < nSeconds; }

    bool IsPingedWithin(int nSeconds, int64_t nTimeToCheckAt = -1) {
        if(!lastPing) return false;

        if(nTimeToCheckAt == -1) {
            nTimeToCheckAt = GetAdjustedTime();
        }
        return nTimeToCheckAt - lastPing.sigTime < nSeconds;
    }

    bool IsEnabled() const { return nActiveState == MASTERNODE_ENABLED; }
    bool IsPreEnabled() const { return nActiveState == MASTERNODE_PRE_ENABLED; }
    bool IsPoSeBanned() const { return nActiveState == MASTERNODE_POSE_BAN; }
    // NOTE: this one relies on nPoSeBanScore, not on nActiveState as everything else here
    bool IsPoSeVerified() const { return nPoSeBanScore <= -MASTERNODE_POSE_BAN_MAX_SCORE; }
    bool IsExpired() const { return nActiveState == MASTERNODE_EXPIRED; }
    bool IsOutpointSpent() const { return nActiveState == MASTERNODE_OUTPOINT_SPENT; }
    bool IsUpdateRequired() const { return nActiveState == MASTERNODE_UPDATE_REQUIRED; }
    bool IsSentinelPingExpired() const { return nActiveState == MASTERNODE_SENTINEL_PING_EXPIRED; }
    bool IsNewStartRequired() const { return nActiveState == MASTERNODE_NEW_START_REQUIRED; }

    static bool IsValidStateForAutoStart(int nActiveStateIn) {
        return  nActiveStateIn == MASTERNODE_ENABLED ||
                nActiveStateIn == MASTERNODE_PRE_ENABLED ||
                nActiveStateIn == MASTERNODE_EXPIRED ||
                nActiveStateIn == MASTERNODE_SENTINEL_PING_EXPIRED;
    }

    bool IsValidForPayment() const {
        if(nActiveState == MASTERNODE_ENABLED) {
            return true;
        }
        if (nActiveState == MASTERNODE_SENTINEL_PING_EXPIRED) {
            return true;
        }
        return false;
    }

    bool IsValidNetAddr();
    static bool IsValidNetAddr(CService addrIn);

    void IncreasePoSeBanScore() { if(nPoSeBanScore < MASTERNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore++; }
    void DecreasePoSeBanScore() { if(nPoSeBanScore > -MASTERNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore--; }
    void PoSeBan() { nPoSeBanScore = MASTERNODE_POSE_BAN_MAX_SCORE; }

    CMasternodeBase GetInfo() const;

    static std::string StateToString(int nStateIn);
    std::string GetStateString() const;
    std::string GetStatus() const;

    int GetLastPaidTime() const { return nTimeLastPaid; }
    int GetLastPaidBlock() const { return nBlockLastPaid; }
    CScript GetPayScript () const { return GetScriptForDestination(pubKeyCollateralAddress.GetID()); }

    CMasternode& operator=(CMasternode const& from) {
        static_cast<CMasternodeBase&>(*this)=from;
        lastPing = from.lastPing;
        vchSig = from.vchSig;
        nCollateralMinConfBlockHash = from.nCollateralMinConfBlockHash;
        nBlockLastPaid = from.nBlockLastPaid;
        nPoSeBanScore = from.nPoSeBanScore;
        nPoSeBanHeight = from.nPoSeBanHeight;
        fAllowMixingTx = from.fAllowMixingTx;
        fUnitTest = from.fUnitTest;
        return *this;
    }
    void Dump (const std::string& border, std::function<void(std::string)> dumpfunc);
};

inline bool operator==(const CMasternode& a, const CMasternode& b) {
    return a.outpoint == b.outpoint;
}

inline bool operator!=(const CMasternode& a, const CMasternode& b) {
    return !(a.outpoint == b.outpoint);
}

//
// The Masternode Broadcast Class : Contains a different serialize method for sending masternodes through the network
//

class CMasternodeBroadcast : public CMasternode {
public:
    bool fRecovery;

    CMasternodeBroadcast() : CMasternode(), fRecovery(false) {}
    CMasternodeBroadcast(const CMasternode& mn) : CMasternode(mn), fRecovery(false) {}
    CMasternodeBroadcast(CService addrNew, COutPoint outpointNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyMasternodeNew, int nProtocolVersionIn) :
        CMasternode(addrNew, outpointNew, pubKeyCollateralAddressNew, pubKeyMasternodeNew, nProtocolVersionIn), fRecovery(false) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(outpoint);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyMasternode);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
        READWRITE(sigTime);
        READWRITE(nProtocolVersion);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(lastPing);
        }
    }

    uint256 GetHash() const;

    /// Create Masternode broadcast, needs to be relayed manually after that
    static bool Create(const COutPoint& outpoint, const CService& service, const CKey& keyCollateralAddressNew, const CPubKey& pubKeyCollateralAddressNew, const CKey& keyMasternodeNew, const CPubKey& pubKeyMasternodeNew, std::string &strErrorRet, CMasternodeBroadcast &mnbRet);
    static bool Create(const std::string& strService, const std::string& strKey, const std::string& strTxHash, const std::string& strOutputIndex, std::string& strErrorRet, CMasternodeBroadcast &mnbRet, bool fOffline = false);

    bool SimpleCheck(int& nDos);
    bool Update(CMasternode* pmn, int& nDos, CConnman& connman);
    bool CheckOutpoint(int& nDos);

    bool Sign(const CKey& keyCollateralAddress);
    bool CheckSignature(int& nDos) const;
    void Relay(CConnman& connman) const;
};

class CMasternodeVerification {
public:
    COutPoint masternodeOutpoint1{};
    COutPoint masternodeOutpoint2{};
    CService addr{};
    int nonce{};
    int nBlockHeight{};
    std::vector<unsigned char> vchSig1{};
    std::vector<unsigned char> vchSig2{};

    CMasternodeVerification() = default;

    CMasternodeVerification(CService addr, int nonce, int nBlockHeight) :
        addr(addr),
        nonce(nonce),
        nBlockHeight(nBlockHeight)
    {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(masternodeOutpoint1);
        READWRITE(masternodeOutpoint2);
        READWRITE(addr);
        READWRITE(nonce);
        READWRITE(nBlockHeight);
        READWRITE(vchSig1);
        READWRITE(vchSig2);
    }

    uint256 GetHash() const {
        // Note: doesn't match serialization

        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        // adding dummy values here to match old hashing format
        ss << masternodeOutpoint1 << uint8_t{} << 0xffffffff;
        ss << masternodeOutpoint2 << uint8_t{} << 0xffffffff;
        ss << addr;
        ss << nonce;
        ss << nBlockHeight;
        return ss.GetHash();
    }

    uint256 GetSignatureHash1(const uint256& blockHash) const {
        // Note: doesn't match serialization

        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << addr;
        ss << nonce;
        ss << blockHash;
        return ss.GetHash();
    }

    uint256 GetSignatureHash2(const uint256& blockHash) const {
        // Note: doesn't match serialization

        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << masternodeOutpoint1;
        ss << masternodeOutpoint2;
        ss << addr;
        ss << nonce;
        ss << blockHash;
        return ss.GetHash();
    }

    void Relay() const {
        CInv inv(MSG_MASTERNODE_VERIFY, GetHash());
        g_connman->ForEachNode([&inv](CNode* pnode) {
            pnode->PushInventory(inv);
        });
    }
};

// masternode-payments

class CMasternodePaymentVote;

static const int MNPAYMENTS_SIGNATURES_REQUIRED         = 15;
static const int MNPAYMENTS_SIGNATURES_TOTAL            = 50;

extern CCriticalSection cs_vecPayees;
extern CCriticalSection cs_mapMasternodeBlocks;
extern CCriticalSection cs_mapMasternodePayeeVotes;

class CMasternodePayee {
private:
    CScript scriptPubKey;
    std::vector<uint256> vecVoteHashes;

public:
    CMasternodePayee() : scriptPubKey(), vecVoteHashes() {
        
    }

    CMasternodePayee(CScript payee, uint256 hashIn) : scriptPubKey(payee), vecVoteHashes() {
        vecVoteHashes.push_back(hashIn);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(vecVoteHashes);
    }

    CScript GetPayee() const { return scriptPubKey; }

    void AddVoteHash(uint256 hashIn) { vecVoteHashes.push_back(hashIn); }
    std::vector<uint256> GetVoteHashes() const { return vecVoteHashes; }
    int GetVoteCount() const { return vecVoteHashes.size(); }
};

// Keep track of votes for payees from masternodes
class CMasternodeBlockPayees {
public:
    int nBlockHeight;
    std::vector<CMasternodePayee> vecPayees;

    CMasternodeBlockPayees() : nBlockHeight(0), vecPayees() {
        // nothing
    }
    CMasternodeBlockPayees(int nBlockHeightIn) : nBlockHeight(nBlockHeightIn), vecPayees() {
        // nothing
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBlockHeight);
        READWRITE(vecPayees);
    }

    void AddPayee(const CMasternodePaymentVote& vote);
    bool GetBestPayee(CScript& payeeRet) const;
    bool HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq) const;

    bool IsTransactionValid(const CTransaction& txNew) const;

    std::string GetRequiredPaymentsString() const;
};

// vote for the winning payment
class CMasternodePaymentVote {
public:
    COutPoint masternodeOutpoint;

    int nBlockHeight;
    CScript payee;
    std::vector<unsigned char> vchSig;

    CMasternodePaymentVote() : masternodeOutpoint(), nBlockHeight(0), payee(), vchSig() {
        // nothing
    }

    CMasternodePaymentVote(COutPoint outpoint, int nBlockHeight, CScript payee) :
        masternodeOutpoint(outpoint), nBlockHeight(nBlockHeight), payee(payee), vchSig() {
        // nothing
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(masternodeOutpoint);
        READWRITE(nBlockHeight);
        READWRITE(*(CScriptBase*)(&payee));
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

    uint256 GetHash() const;

    bool Sign();
    bool CheckSignature(const CPubKey& pubKeyMasternode, int nValidationHeight, int &nDos) const;

    bool IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman) const;
    void Relay(CConnman& connman) const;

    bool IsVerified() const { return !vchSig.empty(); }
    void MarkAsNotVerified() { vchSig.clear(); }

    std::string ToString() const;
};

//
// Masternode Payments Class
// Keeps track of who should get paid for which blocks
//

class CMasternodePayments {
private:
    // masternode count times nStorageCoeff payments blocks should be stored ...
    const float nStorageCoeff;
    // ... but at least nMinBlocksToStore (payments blocks)
    const int nMinBlocksToStore;

    // Keep track of current block height
    int nCachedBlockHeight;

public:
    std::map<uint256, CMasternodePaymentVote> mapMasternodePaymentVotes;
    std::map<int, CMasternodeBlockPayees> mapMasternodeBlocks;
    std::map<COutPoint, int> mapMasternodesLastVote;
    std::map<COutPoint, int> mapMasternodesDidNotVote;

    CMasternodePayments() : nStorageCoeff(1.5), nMinBlocksToStore(2000) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mapMasternodePaymentVotes);
        READWRITE(mapMasternodeBlocks);
    }

    void Clear();

    bool AddOrUpdatePaymentVote(const CMasternodePaymentVote& vote);
    bool HasVerifiedPaymentVote(const uint256& hashIn) const;
    bool ProcessBlock(int nBlockHeight, CConnman& connman);
    void CheckBlockVotes(int nBlockHeight);

    void Sync(CNode* node, CConnman& connman) const;
    void RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman) const;
    void CheckAndRemove();

    bool GetBlockPayee(int nBlockHeight, CScript& payeeRet) const;
    bool IsTransactionValid(const CTransaction& txNew, int nBlockHeight) const;
    bool IsScheduled(const CMasternodeBase& mnInfo, int nNotBlockHeight) const;

    bool UpdateLastVote(const CMasternodePaymentVote& vote);

    bool ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);
    std::string GetRequiredPaymentsString(int nBlockHeight) const;
    void FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutMasternodeRet) const;
    std::string ToString() const;

    int GetBlockCount() const { return mapMasternodeBlocks.size(); }
    int GetVoteCount() const { return mapMasternodePaymentVotes.size(); }

    bool IsEnoughData() const;
    int GetStorageLimit() const;

    void UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman);
    void Dump (const std::string& border, std::function<void(std::string)> dumpfunc);
}; 

extern CMasternodePayments mnpayments;

bool IsBlockPaymentsValid (const CTransaction& txNew, int nBlockHeight, CAmount blockReward);
void FillBlockPayments (CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward);

// masternode-sync

static const int MASTERNODE_SYNC_FAILED          = -1;
static const int MASTERNODE_SYNC_INITIAL         = 0; // sync just started, was reset recently or still in IDB
static const int MASTERNODE_SYNC_WAITING         = 1; // waiting after initial to see if we can get more headers/blocks
static const int MASTERNODE_SYNC_LIST            = 2;
static const int MASTERNODE_SYNC_MNW             = 3;
static const int MASTERNODE_SYNC_GOVERNANCE      = 4;
static const int MASTERNODE_SYNC_GOVOBJ          = 10;
static const int MASTERNODE_SYNC_GOVOBJ_VOTE     = 11;
static const int MASTERNODE_SYNC_FINISHED        = 999;

static const int MASTERNODE_SYNC_TICK_SECONDS    = 6;
static const int MASTERNODE_SYNC_TIMEOUT_SECONDS = 30; // our blocks are 2.5 minutes so 30 seconds should be fine

static const int MASTERNODE_SYNC_ENOUGH_PEERS    = 6;

class CMasternodeSync {
private:
    // Keep track of current asset
    int nRequestedMasternodeAssets;
    // Count peers we've requested the asset from
    int nRequestedMasternodeAttempt;

    // Time when current masternode asset sync started
    int64_t nTimeAssetSyncStarted;
    // ... last bumped
    int64_t nTimeLastBumped;
    // ... or failed
    int64_t nTimeLastFailure;

    void Fail();

public:
    CMasternodeSync() { Reset(); }

    bool IsFailed() { return nRequestedMasternodeAssets == MASTERNODE_SYNC_FAILED; }
    bool IsBlockchainSynced() { return nRequestedMasternodeAssets > MASTERNODE_SYNC_WAITING; }
    bool IsMasternodeListSynced() { return nRequestedMasternodeAssets > MASTERNODE_SYNC_LIST; }
    bool IsWinnersListSynced() { return nRequestedMasternodeAssets > MASTERNODE_SYNC_MNW; }
    bool IsSynced() { return nRequestedMasternodeAssets == MASTERNODE_SYNC_FINISHED; }

    int GetAssetID() { return nRequestedMasternodeAssets; }
    int GetAttempt() { return nRequestedMasternodeAttempt; }
    void BumpAssetLastTime(const std::string& strFuncName);
    int64_t GetAssetStartTime() { return nTimeAssetSyncStarted; }
    std::string GetAssetName();
    std::string GetSyncStatus();

    void Reset();
    void SwitchToNextAsset(CConnman& connman);

    bool ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);
    void ProcessTick(CConnman& connman);

    void NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman);
    void UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman);
}; 

extern CMasternodeSync masternodeSync;

// masternodeman

class CMasternodeMan {
public:
    typedef std::pair<arith_uint256, const CMasternode*> score_pair_t;
    typedef std::vector<score_pair_t> score_pair_vec_t;
    typedef std::pair<int, const CMasternode> rank_pair_t;
    typedef std::vector<rank_pair_t> rank_pair_vec_t;

private:
    static const std::string SERIALIZATION_VERSION_STRING;

    static const int DSEG_UPDATE_SECONDS        = 2 * 60 * 60;

    static const int LAST_PAID_SCAN_BLOCKS;

    static const int MAX_POSE_CONNECTIONS       = 10;
    static const int MAX_POSE_RANK              = 10;
    static const int MAX_POSE_BLOCKS            = 10;

    static const int MNB_RECOVERY_QUORUM_TOTAL      = 10;
    static const int MNB_RECOVERY_QUORUM_REQUIRED   = 6;
    static const int MNB_RECOVERY_MAX_ASK_ENTRIES   = 10;
    static const int MNB_RECOVERY_WAIT_SECONDS      = 60;
    static const int MNB_RECOVERY_RETRY_SECONDS     = 2 * 60 * 60;

    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // Keep track of current block height
    int nCachedBlockHeight;

    // map to hold all MNs
    std::map<COutPoint, CMasternode> mapMasternodes;
    // who's asked for the Masternode list and the last time
    std::map<CService, int64_t> mAskedUsForMasternodeList;
    // who we asked for the Masternode list and the last time
    std::map<CService, int64_t> mWeAskedForMasternodeList;
    // which Masternodes we've asked for
    std::map<COutPoint, std::map<CService, int64_t> > mWeAskedForMasternodeListEntry;

    // who we asked for the masternode verification
    std::map<CService, CMasternodeVerification> mWeAskedForVerification;

    // these maps are used for masternode recovery from MASTERNODE_NEW_START_REQUIRED state
    std::map<uint256, std::pair< int64_t, std::set<CService>>> mMnbRecoveryRequests;
    std::map<uint256, std::vector<CMasternodeBroadcast>> mMnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256>> listScheduledMnbRequestConnections;
    std::map<CService, std::pair<int64_t, std::set<uint256>>> mapPendingMNB;
    std::map<CService, std::pair<int64_t, CMasternodeVerification>> mapPendingMNV;
    CCriticalSection cs_mapPendingMNV;

    /// Set when masternodes are added, cleared when CGovernanceManager is notified
    bool fMasternodesAdded;

    /// Set when masternodes are removed, cleared when CGovernanceManager is notified
    bool fMasternodesRemoved;

    int64_t nLastSentinelPingTime;

    friend class CMasternodeSync;
    /// Find an entry
    CMasternode* Find(const COutPoint& outpoint);

    bool GetMasternodeScores(const uint256& nBlockHash, score_pair_vec_t& vecMasternodeScoresRet, int nMinProtocol = 0);

    void SyncSingle(CNode* pnode, const COutPoint& outpoint, CConnman& connman);
    void SyncAll(CNode* pnode, CConnman& connman);

    void PushDsegInvs(CNode* pnode, const CMasternode& mn);

public:
    // Keep track of all broadcasts I've seen
    std::map<uint256, std::pair<int64_t, CMasternodeBroadcast> > mapSeenMasternodeBroadcast;
    // Keep track of all pings I've seen
    std::map<uint256, CMasternodePing> mapSeenMasternodePing;
    // Keep track of all verifications I've seen
    std::map<uint256, CMasternodeVerification> mapSeenMasternodeVerification;
    // keep track of dsq count to prevent masternodes from gaming darksend queue
    int64_t nDsqCount;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        std::string strVersion;
        if (ser_action.ForRead()) {
            READWRITE(strVersion);
        } else {
            strVersion = SERIALIZATION_VERSION_STRING; 
            READWRITE(strVersion);
        }

        READWRITE(mapMasternodes);
        READWRITE(mAskedUsForMasternodeList);
        READWRITE(mWeAskedForMasternodeList);
        READWRITE(mWeAskedForMasternodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastSentinelPingTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenMasternodeBroadcast);
        READWRITE(mapSeenMasternodePing);
        if (ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CMasternodeMan();

    /// Add an entry
    bool Add(CMasternode &mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, const COutPoint& outpoint, CConnman& connman);
    void AskForMnb(CNode *pnode, const uint256 &hash);

    bool PoSeBan(const COutPoint &outpoint);
    bool AllowMixing(const COutPoint &outpoint);
    bool DisallowMixing(const COutPoint &outpoint);

    /// Check all Masternodes
    void Check();

    /// Check all Masternodes and remove inactive
    void CheckAndRemove(CConnman& connman);
    /// This is dummy overload to be used for dumping/loading mncache.dat
    void CheckAndRemove() {}

    /// Clear Masternode vector
    void Clear();

    /// Count Masternodes filtered by nProtocolVersion.
    /// Masternode nProtocolVersion should match or be above the one specified in param here.
    int CountMasternodes(int nProtocolVersion = -1);
    /// Count enabled Masternodes filtered by nProtocolVersion.
    /// Masternode nProtocolVersion should match or be above the one specified in param here.
    int CountEnabled(int nProtocolVersion = -1);

    /// Count Masternodes by network type - NET_IPV4, NET_IPV6, NET_TOR
    // int CountByIP(int nNetworkType);

    void DsegUpdate(CNode* pnode, CConnman& connman);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const COutPoint& outpoint, CMasternode& masternodeRet);
    bool Has(const COutPoint& outpoint);

    bool GetMasternodeInfo(const COutPoint& outpoint, CMasternodeBase& mnInfoRet);
    bool GetMasternodeInfo(const CPubKey& pubKeyMasternode, CMasternodeBase& mnInfoRet);
    bool GetMasternodeInfo(const CScript& payee, CMasternodeBase& mnInfoRet);

    /// Find an entry in the masternode list that is next to be paid
    bool GetNextMasternodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCountRet, CMasternodeBase& mnInfoRet);
    /// Same as above but use current block height
    bool GetNextMasternodeInQueueForPayment(bool fFilterSigTime, int& nCountRet, CMasternodeBase& mnInfoRet);

    /// Find a random entry
    CMasternodeBase FindRandomNotInVec(const std::vector<COutPoint> &vecToExclude, int nProtocolVersion = -1);

    std::map<COutPoint, CMasternode> GetFullMasternodeMap() { return mapMasternodes; }

    void ForEach (std::function<bool(CMasternode& mn)> func) {
        LOCK(cs);
        for (auto& it : mapMasternodes) 
            if (!func(it.second)) return;
    }

    void ForEachConst (std::function<bool(const CMasternode& mn)> func) const {
        LOCK(cs);
        for (const auto& it : mapMasternodes) 
            if (!func(it.second)) return;
    }

    bool GetMasternodeRanks(rank_pair_vec_t& vecMasternodeRanksRet, int nBlockHeight = -1, int nMinProtocol = 0);
    bool GetMasternodeRank(const COutPoint &outpoint, int& nRankRet, int nBlockHeight = -1, int nMinProtocol = 0);

    void ProcessMasternodeConnections(CConnman& connman);
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();
    void ProcessPendingMnbRequests(CConnman& connman);

    bool ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);

    void DoFullVerificationStep(CConnman& connman);
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<const CMasternode*>& vSortedByAddr, CConnman& connman);
    void ProcessPendingMnvRequests(CConnman& connman);
    void SendVerifyReply(CNode* pnode, CMasternodeVerification& mnv, CConnman& connman);
    void ProcessVerifyReply(CNode* pnode, CMasternodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CMasternodeVerification& mnv);

    /// Return the number of (unique) Masternodes
    int size() { return mapMasternodes.size(); }

    std::string ToString() const;

    /// Perform complete check and only then update masternode list and maps using provided CMasternodeBroadcast
    bool CheckMnbAndUpdateMasternodeList(CNode* pfrom, CMasternodeBroadcast mnb, int& nDos, CConnman& connman);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    bool IsSentinelPingActive();
    void UpdateLastSentinelPingTime();

    void CheckMasternode(const CPubKey& pubKeyMasternode, bool fForce);

    bool IsMasternodePingedWithin(const COutPoint& outpoint, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetMasternodeLastPing(const COutPoint& outpoint, const CMasternodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    void WarnMasternodeDaemonUpdates();

    /**
     * Called to notify CGovernanceManager that the masternode index has been updated.
     * Must be called while not holding the CMasternodeMan::cs mutex
     */
    void NotifyMasternodeUpdates(CConnman& connman);
    void Dump (const std::string& border, std::function<void(std::string)> dumpfunc);
};
 
extern CMasternodeMan mnodeman;

// masternodeconfig

class CMasternodeConfig {
public:
    class CMasternodeEntry {
    private:
        std::string alias;
        std::string ip;
        std::string privKey;
        std::string txHash;
        std::string outputIndex;
    public:
        CMasternodeEntry (const std::string& alias, const std::string& ip, const std::string& privKey, 
                    const std::string& txHash, const std::string& outputIndex) {
            this->alias = alias;
            this->ip = ip;
            this->privKey = privKey;
            this->txHash = txHash;
            this->outputIndex = outputIndex;
        }

        const std::string& getAlias() const {
            return alias;
        }

        void setAlias(const std::string& alias) {
            this->alias = alias;
        }

        const std::string& getOutputIndex() const {
            return outputIndex;
        }

        void setOutputIndex(const std::string& outputIndex) {
            this->outputIndex = outputIndex;
        }

        const std::string& getPrivKey() const {
            return privKey;
        }

        void setPrivKey(const std::string& privKey) {
            this->privKey = privKey;
        }

        const std::string& getTxHash() const {
            return txHash;
        }

        void setTxHash(const std::string& txHash) {
            this->txHash = txHash;
        }

        const std::string& getIp() const {
            return ip;
        }

        void setIp(const std::string& ip) {
            this->ip = ip;
        }
    };

    CMasternodeConfig() {
        entries = std::vector<CMasternodeEntry>();
    }

    void clear();
    bool read(std::string& strErrRet);
    bool write(std::string& strErrRet);
    void add(const std::string& alias, const std::string& ip, const std::string& privKey, const std::string& txHash, const std::string& outputIndex);

    std::vector<CMasternodeEntry>& getEntries() {
        return entries;
    }

    int getCount() {
        return (int)entries.size();
    }

private:
    std::vector<CMasternodeEntry> entries;
}; 

void load_mn_dat ();
void save_mn_dat ();

extern CMasternodeConfig masternodeConfig;

fs::path GetMasternodeConfigFile();

// activemasternode

static const int ACTIVE_MASTERNODE_INITIAL          = 0; // initial state
static const int ACTIVE_MASTERNODE_SYNC_IN_PROCESS  = 1;
static const int ACTIVE_MASTERNODE_INPUT_TOO_NEW    = 2;
static const int ACTIVE_MASTERNODE_NOT_CAPABLE      = 3;
static const int ACTIVE_MASTERNODE_STARTED          = 4;

// Responsible for activating the Masternode and pinging the network
class CActiveMasternode
{
public:
    enum masternode_type_enum_t {
        MASTERNODE_UNKNOWN = 0,
        MASTERNODE_REMOTE  = 1
    };

private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    masternode_type_enum_t eType;

    bool fPingerEnabled;

    /// Ping Masternode
    bool SendMasternodePing(CConnman& connman);

    //  sentinel ping data
    int64_t nSentinelPingTime;
    uint32_t nSentinelVersion;

public:
    // Keys for the active Masternode
    CPubKey pubKeyMasternode;
    CKey keyMasternode;

    // Initialized while registering Masternode
    COutPoint outpoint;
    CService service;

    int nState; // should be one of ACTIVE_MASTERNODE_XXXX
    std::string strNotCapableReason;


    CActiveMasternode()
        : eType(MASTERNODE_UNKNOWN),
          fPingerEnabled(false),
          pubKeyMasternode(),
          keyMasternode(),
          outpoint(),
          service(),
          nState(ACTIVE_MASTERNODE_INITIAL)
    {}

    /// Manage state of active Masternode
    void ManageState(CConnman& connman);
    bool DoAnnounce (CConnman& connman, std::string& strError);

    std::string GetStateString() const;
    std::string GetStatus() const;
    std::string GetTypeString() const;

    bool UpdateSentinelPing(int version);

private:
    void ManageStateInitial(CConnman& connman);
    void ManageStateRemote();
};

extern CActiveMasternode activeMasternode;

extern bool fMasternodeMode;

// messagesigner

class CMessageSigner
{
public:
    /// Set the private/public key values, returns true if successful
    static bool GetKeysFromSecret(const std::string& strSecret, CKey& keyRet, CPubKey& pubkeyRet);
    /// Sign the message, returns true if successful
    static bool SignMessage(const std::string& strMessage, std::vector<unsigned char>& vchSigRet, const CKey& key);
    /// Verify the message signature, returns true if succcessful
    static bool VerifyMessage(const CPubKey& pubkey, const std::vector<unsigned char>& vchSig, const std::string& strMessage, std::string& strErrorRet);
    /// Verify the message signature, returns true if succcessful
    static bool VerifyMessage(const CKeyID& keyID, const std::vector<unsigned char>& vchSig, const std::string& strMessage, std::string& strErrorRet);
};

// netfulfilledman

// Fulfilled requests are used to prevent nodes from asking for the same data on sync
// and from being banned for doing so too often.
class CNetFulfilledRequestManager {
private:
    std::map<std::string, int64_t> mapFulfilledRequests;
    CCriticalSection cs_mapFulfilledRequests;
    void RemoveFulfilledRequest(const CService& addr, const std::string& strRequest);

public:
    CNetFulfilledRequestManager() {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs_mapFulfilledRequests);
        READWRITE(mapFulfilledRequests);
    }

    void AddFulfilledRequest(const CService& addr, const std::string& strRequest);
    bool HasFulfilledRequest(const CService& addr, const std::string& strRequest);

    void CheckAndRemove();
    void Clear();

    std::string ToString() const;
};

extern CNetFulfilledRequestManager netfulfilledman;

// dsnotificationinterface

class CDSNotificationInterface : public CValidationInterface
{
public:
    CDSNotificationInterface(CConnman& connmanIn): connman(connmanIn) {}
    virtual ~CDSNotificationInterface() = default;

    // a small helper to initialize current block height in sub-modules on startup
    void InitializeCurrentBlockTip();

protected:
    // CValidationInterface
    void NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload) override;
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;
    void BlockConnected(const std::shared_ptr<const CBlock> &pblock, const CBlockIndex *pindex, 
        const std::vector<CTransactionRef> &vtxConflicted) override;

private:
    CConnman& connman;
};

// newest protect

class CVote {
public:
    CService addr{};                      // 20
    uint256 block_hash{};                 // 32
    int block_height{0};                  //  4
    CService verify_addr{};               // 20
    CKeyID reward{};                      // 20
    std::vector<unsigned char> sig{};     // 65
    int state{0};

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(addr);
        READWRITE(block_hash);
        READWRITE(block_height);
        READWRITE(verify_addr);
        READWRITE(reward);
        READWRITE(sig);
    }

    uint256 hash () const {
        CHashWriter hasher (SER_GETHASH, PROTOCOL_VERSION);
        hasher << addr << block_hash << block_height << verify_addr << reward;
        return hasher.GetHash();
    }

    bool check ();

    bool sign ();

    void dump (const std::string& border, std::function<void(std::string)> dumpfunc);
};

class CVotes {
public:
    CKey key;
    CPubKey pubkey;
    CService netaddr;

    using CHashHei = std::pair<int, uint256>;
    using CNodeID = std::pair<CService, CKeyID>;
    using CNodeInfo = std::function<void(const CNodeID&, const CHashHei&, const CHashHei&)>;

    CCriticalSection cs_pay;
    std::map<CHashHei, CKeyID> mapPayouts;

    CCriticalSection cs;
    std::map<uint256, CVote> mapVotes, mapUnchecked;
    std::map<CHashHei, std::set<CNodeID> > cacheVoting;             // HashID = from
    std::map<CNodeID, std::pair<CHashHei, CHashHei> > cacheNodes;   // CNodeID = lastpaid, lastseen
    std::map<CNodeID, std::map<CNodeID, CHashHei> > cacheVerify;    // <to, from>, HashID

    CBlockIndex* last_index{};

    bool exist (const uint256& hash);
    void add (const uint256& hash, CVote& vote);
    //void load ();
    //void save ();

    bool ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);
    void UpdatedBlockTip (const CBlockIndex *pindex); 
    void BlockConnected (const std::shared_ptr<const CBlock> &pblock, const CBlockIndex *pindex);

    void update_pay (const uint256& block_hash, int height, const CTransaction& tx);
    int get_payheight (const CKeyID& addr);
    uint256 calc_blockhash (int block_height);
    CKeyID calc_payaddr (int block_height);

    void enum_nodes (CNodeInfo enumfunc);                           // CNodeID, lastpaid, lastseen
    void dump (const std::string& border, std::function<void(std::string)> dumpfunc);
};

extern CVotes votes;

#endif