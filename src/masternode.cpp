// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2021-2025 Uladzimir (t.me/vovanchik_net)
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode.h>

#include <key_io.h>
#include <core_io.h>
#include <clientversion.h>
#include <init.h>
#include <netbase.h>
#include <net_processing.h>
#include <script/standard.h>
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif // ENABLE_WALLET
#include <shutdown.h>
#include <consensus/validation.h>
#include <netmessagemaker.h>
#include <checkpoints.h>
#include <ui_interface.h>
#include <addrman.h>
#include <warnings.h>
#include <txdb.h>
#include <util.h>
#include <utilstrencodings.h> 
#include <utilmoneystr.h> 
#include <chainparams.h>

#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <protocol.h>
#include <hash.h>
#include <validation.h>
#include <tinyformat.h>

std::string script2addr (const CScript& script) {
    std::string ret = "";
    CTxDestination address;
    if (ExtractDestination(script, address)) ret = EncodeDestination (address);
    if (ret.empty()) ret = ScriptToAsmStr (script, true);
    return ret;
}

// masternode

CMasternode::CMasternode() :
    CMasternodeBase{ MASTERNODE_ENABLED, PROTOCOL_VERSION, GetAdjustedTime()},
    fAllowMixingTx(true)
{}

CMasternode::CMasternode(CService addr, COutPoint outpoint, CPubKey pubKeyCollateralAddress, CPubKey pubKeyMasternode, int nProtocolVersionIn) :
    CMasternodeBase{ MASTERNODE_ENABLED, nProtocolVersionIn, GetAdjustedTime(),
                       outpoint, addr, pubKeyCollateralAddress, pubKeyMasternode},
    fAllowMixingTx(true)
{}

CMasternode::CMasternode(const CMasternode& other) :
    CMasternodeBase{other},
    lastPing(other.lastPing),
    vchSig(other.vchSig),
    nCollateralMinConfBlockHash(other.nCollateralMinConfBlockHash),
    nBlockLastPaid(other.nBlockLastPaid),
    nPoSeBanScore(other.nPoSeBanScore),
    nPoSeBanHeight(other.nPoSeBanHeight),
    fAllowMixingTx(other.fAllowMixingTx),
    fUnitTest(other.fUnitTest)
{}

CMasternode::CMasternode(const CMasternodeBroadcast& mnb) :
    CMasternodeBase{ mnb.nActiveState, mnb.nProtocolVersion, mnb.sigTime,
                       mnb.outpoint, mnb.addr, mnb.pubKeyCollateralAddress, mnb.pubKeyMasternode},
    lastPing(mnb.lastPing),
    vchSig(mnb.vchSig),
    fAllowMixingTx(true)
{}

//
// When a new masternode broadcast is sent, update our information
//
bool CMasternode::UpdateFromNewBroadcast(CMasternodeBroadcast& mnb, CConnman& connman)
{
    if(mnb.sigTime <= sigTime && !mnb.fRecovery) return false;

    pubKeyMasternode = mnb.pubKeyMasternode;
    sigTime = mnb.sigTime;
    vchSig = mnb.vchSig;
    nProtocolVersion = mnb.nProtocolVersion;
    addr = mnb.addr;
    nPoSeBanScore = 0;
    nPoSeBanHeight = 0;
    nTimeLastChecked = 0;
    int nDos = 0;
    if(!mnb.lastPing || (mnb.lastPing && mnb.lastPing.CheckAndUpdate(this, true, nDos, connman))) {
        lastPing = mnb.lastPing;
        mnodeman.mapSeenMasternodePing.insert(std::make_pair(lastPing.GetHash(), lastPing));
    }
    // if it matches our Masternode privkey...
    if(fMasternodeMode && pubKeyMasternode == activeMasternode.pubKeyMasternode) {
        nPoSeBanScore = -MASTERNODE_POSE_BAN_MAX_SCORE;
        if(nProtocolVersion == PROTOCOL_VERSION) {
            // ... and PROTOCOL_VERSION, then we've been remotely activated ...
            activeMasternode.ManageState(connman);
        } else {
            // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
            // but also do not ban the node we get this message from
            LogPrintf("CMasternode::UpdateFromNewBroadcast -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", nProtocolVersion, PROTOCOL_VERSION);
            return false;
        }
    }
    return true;
}

//
// Deterministically calculate a given "score" for a Masternode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
arith_uint256 CMasternode::CalculateScore(const uint256& blockHash) const
{
    // Deterministically calculate a "score" for a Masternode based on any given (block)hash
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << outpoint << nCollateralMinConfBlockHash << blockHash;
    return UintToArith256(ss.GetHash());
}

CMasternode::CollateralStatus CMasternode::CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey)
{
    int nHeight;
    return CheckCollateral(outpoint, pubkey, nHeight);
}

CMasternode::CollateralStatus CMasternode::CheckCollateral(const COutPoint& outpoint, const CPubKey& pubkey, int& nHeightRet)
{
    AssertLockHeld(cs_main);

    Coin coin;
    if(!GetUTXOCoin(outpoint, coin)) {
        return COLLATERAL_UTXO_NOT_FOUND;
    }

    if(coin.out.nValue != Params().GetConsensus().nMasternodeAmountLock * COIN) {
        return COLLATERAL_INVALID_AMOUNT;
    }

    if(pubkey == CPubKey() || coin.out.scriptPubKey != GetScriptForDestination(pubkey.GetID())) {
        return COLLATERAL_INVALID_PUBKEY;
    }

    nHeightRet = coin.nHeight;
    return COLLATERAL_OK;
}

void CMasternode::Check(bool fForce)
{
    AssertLockHeld(cs_main);
    LOCK(cs);

    if(ShutdownRequested()) return;

    if(!fForce && (GetTime() - nTimeLastChecked < MASTERNODE_CHECK_SECONDS)) return;
    nTimeLastChecked = GetTime();

    LogPrint(BCLog::MN, "CMasternode::Check -- Masternode %s is in %s state\n", outpoint.ToString(), GetStateString());

    //once spent, stop doing the checks
    if(IsOutpointSpent()) return;

    int nHeight = 0;
    if(!fUnitTest) {
        Coin coin;
        if(!GetUTXOCoin(outpoint, coin)) {
            nActiveState = MASTERNODE_OUTPOINT_SPENT;
            LogPrint(BCLog::MN, "CMasternode::Check -- Failed to find Masternode UTXO, masternode=%s\n", outpoint.ToString());
            return;
        }

        nHeight = chainActive.Height();
    }

    if(IsPoSeBanned()) {
        if(nHeight < nPoSeBanHeight) return; // too early?
        // Otherwise give it a chance to proceed further to do all the usual checks and to change its state.
        // Masternode still will be on the edge and can be banned back easily if it keeps ignoring mnverify
        // or connect attempts. Will require few mnverify messages to strengthen its position in mn list.
        LogPrintf("CMasternode::Check -- Masternode %s is unbanned and back in list now\n", outpoint.ToString());
        DecreasePoSeBanScore();
    } else if(nPoSeBanScore >= MASTERNODE_POSE_BAN_MAX_SCORE) {
        nActiveState = MASTERNODE_POSE_BAN;
        // ban for the whole payment cycle
        nPoSeBanHeight = nHeight + mnodeman.size();
        LogPrintf("CMasternode::Check -- Masternode %s is banned till block %d now\n", outpoint.ToString(), nPoSeBanHeight);
        return;
    }

    int nActiveStatePrev = nActiveState;
    bool fOurMasternode = fMasternodeMode && activeMasternode.pubKeyMasternode == pubKeyMasternode;
    
    if (fOurMasternode && IsNewStartRequired()) {
        std::string strError;
        activeMasternode.DoAnnounce (*g_connman, strError);
        LogPrint(BCLog::MN, "CMasternode::Check -- Restarting %s ...\n", outpoint.ToString());
    }

    // keep old masternodes on start, give them a chance to receive updates...
    bool fWaitForPing = !masternodeSync.IsMasternodeListSynced() && !IsPingedWithin(MASTERNODE_MIN_MNP_SECONDS);

    if(fWaitForPing && !fOurMasternode) {
        // ...but if it was already expired before the initial check - return right away
        if(IsExpired() || IsSentinelPingExpired() || IsNewStartRequired()) {
            LogPrint(BCLog::MN, "CMasternode::Check -- Masternode %s is in %s state, waiting for ping\n", outpoint.ToString(), GetStateString());
            return;
        }
    }

    // don't expire if we are still in "waiting for ping" mode unless it's our own masternode
    if(!fWaitForPing || fOurMasternode) {

        if(!IsPingedWithin(MASTERNODE_NEW_START_REQUIRED_SECONDS)) {
            nActiveState = MASTERNODE_NEW_START_REQUIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint(BCLog::MN, "CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToString(), GetStateString());
            }
            return;
        }

        if(!IsPingedWithin(MASTERNODE_EXPIRATION_SECONDS)) {
            nActiveState = MASTERNODE_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint(BCLog::MN, "CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToString(), GetStateString());
            }
            return;
        }

        // part 1: expire based on dashd ping
        bool fSentinelPingActive = masternodeSync.IsSynced() && mnodeman.IsSentinelPingActive();
        bool fSentinelPingExpired = fSentinelPingActive && !IsPingedWithin(MASTERNODE_SENTINEL_PING_MAX_SECONDS);
        LogPrint(BCLog::MN, "CMasternode::Check -- outpoint=%s, GetAdjustedTime()=%d, fSentinelPingExpired=%d\n",
                outpoint.ToString(), GetAdjustedTime(), fSentinelPingExpired);

        if(fSentinelPingExpired) {
            nActiveState = MASTERNODE_SENTINEL_PING_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint(BCLog::MN, "CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToString(), GetStateString());
            }
            return;
        }
    }

    // We require MNs to be in PRE_ENABLED until they either start to expire or receive a ping and go into ENABLED state
    // Works on mainnet/testnet only and not the case on regtest/devnet.
    if (lastPing.sigTime - sigTime < MASTERNODE_MIN_MNP_SECONDS) {
        nActiveState = MASTERNODE_PRE_ENABLED;
        if (nActiveStatePrev != nActiveState) {
            LogPrint(BCLog::MN, "CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToString(), GetStateString());
        }
        return;
    }

    if(!fWaitForPing || fOurMasternode) {
        // part 2: expire based on sentinel info
        bool fSentinelPingActive = masternodeSync.IsSynced() && mnodeman.IsSentinelPingActive();
        bool fSentinelPingExpired = fSentinelPingActive && !lastPing.fSentinelIsCurrent;

        LogPrint(BCLog::MN, "CMasternode::Check -- outpoint=%s, GetAdjustedTime()=%d, fSentinelPingExpired=%d\n",
                outpoint.ToString(), GetAdjustedTime(), fSentinelPingExpired);

        if(fSentinelPingExpired) {
            nActiveState = MASTERNODE_SENTINEL_PING_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint(BCLog::MN, "CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToString(), GetStateString());
            }
            return;
        }
    }

    nActiveState = MASTERNODE_ENABLED; // OK
    if(nActiveStatePrev != nActiveState) {
        LogPrint(BCLog::MN, "CMasternode::Check -- Masternode %s is in %s state now\n", outpoint.ToString(), GetStateString());
    }
}

bool CMasternode::IsValidNetAddr()
{
    return IsValidNetAddr(addr);
}

bool CMasternode::IsValidNetAddr(CService addrIn)
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

CMasternodeBase CMasternode::GetInfo() const
{
    CMasternodeBase info{*this};
    info.nTimeLastPing = lastPing.sigTime;
    info.fInfoValid = true;
    return info;
}

std::string CMasternode::StateToString(int nStateIn)
{
    switch(nStateIn) {
        case MASTERNODE_PRE_ENABLED:            return "PRE_ENABLED";
        case MASTERNODE_ENABLED:                return "ENABLED";
        case MASTERNODE_EXPIRED:                return "EXPIRED";
        case MASTERNODE_OUTPOINT_SPENT:         return "OUTPOINT_SPENT";
        case MASTERNODE_UPDATE_REQUIRED:        return "UPDATE_REQUIRED";
        case MASTERNODE_SENTINEL_PING_EXPIRED:  return "SENTINEL_PING_EXPIRED";
        case MASTERNODE_NEW_START_REQUIRED:     return "NEW_START_REQUIRED";
        case MASTERNODE_POSE_BAN:               return "POSE_BAN";
        default:                                return "UNKNOWN";
    }
}

std::string CMasternode::GetStateString() const
{
    return StateToString(nActiveState);
}

std::string CMasternode::GetStatus() const
{
    // TODO: return smth a bit more human readable here
    return GetStateString();
}

void CMasternode::Dump (const std::string& border, std::function<void(std::string)> dumpfunc) {
    LOCK(cs);
    dumpfunc(border + outpoint.ToString() + " {");
    dumpfunc(border + "    address = " + addr.ToString());
    dumpfunc(border + "    pay_addr = " + EncodeDestination(pubKeyCollateralAddress.GetID()));
    dumpfunc(border + "    status = " + GetStatus());
    dumpfunc(border + "    firstseen = " + EasyFormatDateTime(sigTime));
    dumpfunc(border + "    lastseen = " + EasyFormatDateTime(lastPing.sigTime));
    dumpfunc(border + "    activeseconds = " + itostr(lastPing.sigTime - sigTime));
    dumpfunc(border + "    lastpaidtime = " + EasyFormatDateTime(GetLastPaidTime()));
    dumpfunc(border + "    lastpaidblock = " + itostr(GetLastPaidBlock()));
    dumpfunc(border + "    output = " + HexStr(outpoint.hash) + " : " + itostr(outpoint.n));
    dumpfunc(border + "    _nLastDsq = " + itostr(nLastDsq));
    dumpfunc(border + "    _nPoSeBanScore = " + itostr(nPoSeBanScore));
    dumpfunc(border + "    _nPoSeBanHeight = " + itostr(nPoSeBanHeight));
    dumpfunc(border + "}");
}

#ifdef ENABLE_WALLET
bool CMasternodeBroadcast::Create(const std::string& strService, const std::string& strKeyMasternode, const std::string& strTxHash, const std::string& strOutputIndex, std::string& strErrorRet, CMasternodeBroadcast &mnbRet, bool fOffline)
{
    COutPoint outpoint = COutPoint(uint256S(strTxHash), atoi(strOutputIndex));
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeyMasternodeNew;
    CKey keyMasternodeNew;

    auto Log = [&strErrorRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        LogPrintf("CMasternodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    };

    // Wait for sync to finish because mnb simply won't be relayed otherwise
    if (!fOffline && !masternodeSync.IsSynced())
        return Log("Sync in progress. Must wait until sync is complete to start Masternode");

    if (!CMessageSigner::GetKeysFromSecret(strKeyMasternode, keyMasternodeNew, pubKeyMasternodeNew))
        return Log(strprintf("Invalid masternode key %s", strKeyMasternode));

    if (GetWallets().size() == 0)
        return Log(strprintf("Could not allocate outpoint %s:%s for masternode %s.", strTxHash, strOutputIndex, strService));
    std::shared_ptr<CWallet> pwallet = GetWallets()[0];
    if (!pwallet)
        return Log(strprintf("Could not allocate outpoint %s:%s for masternode %s..", strTxHash, strOutputIndex, strService));
    if (strTxHash.empty())
        return Log(strprintf("Could not allocate outpoint %s:%s for masternode %s...", strTxHash, strOutputIndex, strService));
    Coin coin;
    if (!GetUTXOCoin(outpoint, coin))
        return Log(strprintf("Could not allocate outpoint %s:%s for masternode %s...", strTxHash, strOutputIndex, strService));
    if (coin.out.nValue != Params().GetConsensus().nMasternodeAmountLock * COIN)
        return Log(strprintf("Could not allocate outpoint %s:%s for masternode %s....", strTxHash, strOutputIndex, strService));
    CTxDestination address;
    ExtractDestination(coin.out.scriptPubKey, address);
    CKeyID *keyid = boost::get<CKeyID>(&address);
    if (!keyid)
        return Log(strprintf("Could not allocate outpoint %s:%s for masternode %s.....", strTxHash, strOutputIndex, strService));
    if (!pwallet->GetKey(*keyid, keyCollateralAddressNew)) {
        LogPrintf ("CWallet::GetOutpointAndKeysFromOutput -- Private key for address is not known\n");
        return false;
    }
    pubKeyCollateralAddressNew = keyCollateralAddressNew.GetPubKey();

    CService service;
    if (!Lookup(strService.c_str(), service, 0, false))
        return Log(strprintf("Invalid address %s for masternode.", strService));
    if (service.GetPort() != Params().GetDefaultPort())
        return Log(strprintf("Invalid port %u for masternode %s", service.GetPort(), strService));

    return Create(outpoint, service, keyCollateralAddressNew, pubKeyCollateralAddressNew, keyMasternodeNew, pubKeyMasternodeNew, strErrorRet, mnbRet);
}

bool CMasternodeBroadcast::Create(const COutPoint& outpoint, const CService& service, const CKey& keyCollateralAddressNew, const CPubKey& pubKeyCollateralAddressNew, const CKey& keyMasternodeNew, const CPubKey& pubKeyMasternodeNew, std::string &strErrorRet, CMasternodeBroadcast &mnbRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrint(BCLog::MN, "CMasternodeBroadcast::Create -- pubKeyCollateralAddressNew = %s, pubKeyMasternodeNew.GetID() = %s\n",
            EncodeDestination(pubKeyCollateralAddressNew.GetID()), pubKeyMasternodeNew.GetID().ToString());

    auto Log = [&strErrorRet,&mnbRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        LogPrintf("CMasternodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CMasternodeBroadcast();
        return false;
    };

    CMasternodePing mnp(outpoint);
    if (!mnp.Sign(keyMasternodeNew, pubKeyMasternodeNew))
        return Log(strprintf("Failed to sign ping, masternode=%s", outpoint.ToString()));

    mnbRet = CMasternodeBroadcast(service, outpoint, pubKeyCollateralAddressNew, pubKeyMasternodeNew, PROTOCOL_VERSION);

    if (!mnbRet.IsValidNetAddr())
        return Log(strprintf("Invalid IP address, masternode=%s", outpoint.ToString()));

    mnbRet.lastPing = mnp;
    if (!mnbRet.Sign(keyCollateralAddressNew))
        return Log(strprintf("Failed to sign broadcast, masternode=%s", outpoint.ToString()));

    return true;
}
#endif // ENABLE_WALLET

bool CMasternodeBroadcast::SimpleCheck(int& nDos)
{
    nDos = 0;

    AssertLockHeld(cs_main);

    // make sure addr is valid
    if(!IsValidNetAddr()) {
        LogPrintf("CMasternodeBroadcast::SimpleCheck -- Invalid addr, rejected: masternode=%s  addr=%s\n",
                    outpoint.ToString(), addr.ToString());
        return false;
    }

    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CMasternodeBroadcast::SimpleCheck -- Signature rejected, too far into the future: masternode=%s\n", outpoint.ToString());
        nDos = 1;
        return false;
    }

    // empty ping or incorrect sigTime/unknown blockhash
    if(!lastPing || !lastPing.SimpleCheck(nDos)) {
        // one of us is probably forked or smth, just mark it as expired and check the rest of the rules
        nActiveState = MASTERNODE_EXPIRED;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    if(pubkeyScript.size() != 25) {
        LogPrintf("CMasternodeBroadcast::SimpleCheck -- pubKeyCollateralAddress has the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeyMasternode.GetID());

    if(pubkeyScript2.size() != 25) {
        LogPrintf("CMasternodeBroadcast::SimpleCheck -- pubKeyMasternode has the wrong size\n");
        nDos = 100;
        return false;
    }

    if(addr.GetPort() != Params().GetDefaultPort()) return false;

    return true;
}

bool CMasternodeBroadcast::Update(CMasternode* pmn, int& nDos, CConnman& connman)
{
    nDos = 0;

    AssertLockHeld(cs_main);

    if(pmn->sigTime == sigTime && !fRecovery) {
        // mapSeenMasternodeBroadcast in CMasternodeMan::CheckMnbAndUpdateMasternodeList should filter legit duplicates
        // but this still can happen if we just started, which is ok, just do nothing here.
        return false;
    }

    // this broadcast is older than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    if(pmn->sigTime > sigTime) {
        LogPrintf("CMasternodeBroadcast::Update -- Bad sigTime %d (existing broadcast is at %d) for Masternode %s %s\n",
                      sigTime, pmn->sigTime, outpoint.ToString(), addr.ToString());
        return false;
    }

    pmn->Check();

    // masternode is banned by PoSe
    if(pmn->IsPoSeBanned()) {
        LogPrintf("CMasternodeBroadcast::Update -- Banned by PoSe, masternode=%s\n", outpoint.ToString());
        return false;
    }

    // IsVnAssociatedWithPubkey is validated once in CheckOutpoint, after that they just need to match
    if(pmn->pubKeyCollateralAddress != pubKeyCollateralAddress) {
        LogPrintf("CMasternodeBroadcast::Update -- Got mismatched pubKeyCollateralAddress and outpoint\n");
        nDos = 33;
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CMasternodeBroadcast::Update -- CheckSignature() failed, masternode=%s\n", outpoint.ToString());
        return false;
    }

    // if ther was no masternode broadcast recently or if it matches our Masternode privkey...
    if(!pmn->IsBroadcastedWithin(MASTERNODE_MIN_MNB_SECONDS) || (fMasternodeMode && pubKeyMasternode == activeMasternode.pubKeyMasternode)) {
        // take the newest entry
        LogPrintf("CMasternodeBroadcast::Update -- Got UPDATED Masternode entry: addr=%s\n", addr.ToString());
        if(pmn->UpdateFromNewBroadcast(*this, connman)) {
            pmn->Check();
            Relay(connman);
        }
        masternodeSync.BumpAssetLastTime("CMasternodeBroadcast::Update");
    }

    return true;
}

bool CMasternodeBroadcast::CheckOutpoint(int& nDos)
{
    // we are a masternode with the same outpoint (i.e. already activated) and this mnb is ours (matches our Masternode privkey)
    // so nothing to do here for us
    if(fMasternodeMode && outpoint == activeMasternode.outpoint && pubKeyMasternode == activeMasternode.pubKeyMasternode) {
        return true;
    }

    AssertLockHeld(cs_main);

    int nHeight;
    CollateralStatus err = CheckCollateral(outpoint, pubKeyCollateralAddress, nHeight);
    if (err == COLLATERAL_UTXO_NOT_FOUND) {
        LogPrint(BCLog::MN, "CMasternodeBroadcast::CheckOutpoint -- Failed to find Masternode UTXO, masternode=%s\n", outpoint.ToString());
        return false;
    }

    if (err == COLLATERAL_INVALID_AMOUNT) {
        LogPrint(BCLog::MN, "CMasternodeBroadcast::CheckOutpoint -- Masternode UTXO should have 1000 DASH, masternode=%s\n", outpoint.ToString());
        nDos = 33;
        return false;
    }

    if(err == COLLATERAL_INVALID_PUBKEY) {
        LogPrint(BCLog::MN, "CMasternodeBroadcast::CheckOutpoint -- Masternode UTXO should match pubKeyCollateralAddress, masternode=%s\n", outpoint.ToString());
        nDos = 33;
        return false;
    }

    if(chainActive.Height() - nHeight + 1 < 12) {//Params().GetConsensus().nMasternodeMinimumConfirmations) {
        LogPrintf("CMasternodeBroadcast::CheckOutpoint -- Masternode UTXO must have at least %d confirmations, masternode=%s\n",
                12/*Params().GetConsensus().nMasternodeMinimumConfirmations*/, outpoint.ToString());
        // UTXO is legit but has not enough confirmations.
        // Maybe we miss few blocks, let this mnb be checked again later.
        mnodeman.mapSeenMasternodeBroadcast.erase(GetHash());
        return false;
    }

    LogPrint(BCLog::MN, "CMasternodeBroadcast::CheckOutpoint -- Masternode UTXO verified\n");

    // Verify that sig time is legit, should be at least not earlier than the timestamp of the block
    // at which collateral became nMasternodeMinimumConfirmations blocks deep.
    // NOTE: this is not accurate because block timestamp is NOT guaranteed to be 100% correct one.
    CBlockIndex* pRequiredConfIndex = chainActive[nHeight + 12/*Params().GetConsensus().nMasternodeMinimumConfirmations*/ - 1]; // block where tx got nMasternodeMinimumConfirmations
    if(pRequiredConfIndex->GetBlockTime() > sigTime) {
        LogPrintf("CMasternodeBroadcast::CheckOutpoint -- Bad sigTime %d (%d conf block is at %d) for Masternode %s %s\n",
                  sigTime, 12/*Params().GetConsensus().nMasternodeMinimumConfirmations*/, pRequiredConfIndex->GetBlockTime(), outpoint.ToString(), addr.ToString());
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CMasternodeBroadcast::CheckOutpoint -- CheckSignature() failed, masternode=%s\n", outpoint.ToString());
        return false;
    }

    // remember the block hash when collateral for this masternode had minimum required confirmations
    nCollateralMinConfBlockHash = pRequiredConfIndex->GetBlockHash();

    return true;
}

uint256 CMasternodeBroadcast::GetHash() const
{
    // Note: doesn't match serialization

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << outpoint << uint8_t{} << 0xffffffff; // adding dummy values here to match old hashing format
    ss << pubKeyCollateralAddress;
    ss << sigTime;
    return ss.GetHash();
}

bool CMasternodeBroadcast::Sign(const CKey& keyCollateralAddress)
{
    std::string strError;

    sigTime = GetAdjustedTime();

    {
        std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                        pubKeyCollateralAddress.GetID().ToString() + pubKeyMasternode.GetID().ToString() +
                        boost::lexical_cast<std::string>(nProtocolVersion);

        if (!CMessageSigner::SignMessage(strMessage, vchSig, keyCollateralAddress)) {
            LogPrintf("CMasternodeBroadcast::Sign -- SignMessage() failed\n");
            return false;
        }

        if (!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
            LogPrintf("CMasternodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CMasternodeBroadcast::CheckSignature(int& nDos) const
{
    std::string strError = "";
    nDos = 0;

    {
        std::string strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                        pubKeyCollateralAddress.GetID().ToString() + pubKeyMasternode.GetID().ToString() +
                        boost::lexical_cast<std::string>(nProtocolVersion);

        if (!CMessageSigner::VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)){
            LogPrintf("CMasternodeBroadcast::CheckSignature -- Got bad Masternode announce signature, error: %s\n", strError);
            nDos = 100;
            return false;
        }
    }

    return true;
}

void CMasternodeBroadcast::Relay(CConnman& connman) const
{
    // Do not relay until fully synced
    if(!masternodeSync.IsSynced()) {
        LogPrint(BCLog::MN, "CMasternodeBroadcast::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_MASTERNODE_ANNOUNCE, GetHash());
    connman.ForEachNode([&inv](CNode* pnode) {
        pnode->PushInventory(inv);
    });
}

uint256 CMasternodePing::GetHash() const
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    {
        ss << masternodeOutpoint << uint8_t{} << 0xffffffff; // adding dummy values here to match old hashing format
        ss << sigTime;
    }
    return ss.GetHash();
}

CMasternodePing::CMasternodePing(const COutPoint& outpoint)
{
    LOCK(cs_main);
    if (!chainActive.Tip() || chainActive.Height() < 12) return;

    masternodeOutpoint = outpoint;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    nDaemonVersion = CLIENT_VERSION;
}

bool CMasternodePing::Sign(const CKey& keyMasternode, const CPubKey& pubKeyMasternode)
{
    std::string strError;

    sigTime = GetAdjustedTime();

    {
        std::string strMessage = CTxIn(masternodeOutpoint).ToString() + blockHash.ToString() +
                    boost::lexical_cast<std::string>(sigTime);

        if (!CMessageSigner::SignMessage(strMessage, vchSig, keyMasternode)) {
            LogPrintf("CMasternodePing::Sign -- SignMessage() failed\n");
            return false;
        }

        if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrintf("CMasternodePing::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CMasternodePing::CheckSignature(const CPubKey& pubKeyMasternode, int &nDos) const
{
    std::string strError = "";
    nDos = 0;

    {
        std::string strMessage = CTxIn(masternodeOutpoint).ToString() + blockHash.ToString() +
                    boost::lexical_cast<std::string>(sigTime);

        if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrintf("CMasternodePing::CheckSignature -- Got bad Masternode ping signature, masternode=%s, error: %s\n", masternodeOutpoint.ToString(), strError);
            nDos = 33;
            return false;
        }
    }

    return true;
}

bool CMasternodePing::SimpleCheck(int& nDos)
{
    // don't ban by default
    nDos = 0;

    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CMasternodePing::SimpleCheck -- Signature rejected, too far into the future, masternode=%s\n", masternodeOutpoint.ToString());
        nDos = 1;
        return false;
    }

    {
        AssertLockHeld(cs_main);
        auto mi = LookupBlockIndex(blockHash);
        if (mi == nullptr) {
            LogPrint(BCLog::MN, "CMasternodePing::SimpleCheck -- Masternode ping is invalid, unknown block hash: masternode=%s blockHash=%s\n", masternodeOutpoint.ToString(), blockHash.ToString());
            // maybe we stuck or forked so we shouldn't ban this node, just fail to accept this ping
            // TODO: or should we also request this block?
            return false;
        }
    }

    LogPrint(BCLog::MN, "CMasternodePing::SimpleCheck -- Masternode ping verified: masternode=%s  blockHash=%s  sigTime=%d\n", masternodeOutpoint.ToString(), blockHash.ToString(), sigTime);
    return true;
}

bool CMasternodePing::CheckAndUpdate(CMasternode* pmn, bool fFromNewBroadcast, int& nDos, CConnman& connman)
{
    AssertLockHeld(cs_main);

    // don't ban by default
    nDos = 0;

    if (!SimpleCheck(nDos)) {
        return false;
    }

    if (pmn == nullptr) {
        LogPrint(BCLog::MN, "CMasternodePing::CheckAndUpdate -- Couldn't find Masternode entry, masternode=%s\n", masternodeOutpoint.ToString());
        return false;
    }

    if(!fFromNewBroadcast) {
        if (pmn->IsUpdateRequired()) {
            LogPrint(BCLog::MN, "CMasternodePing::CheckAndUpdate -- masternode protocol is outdated, masternode=%s\n", masternodeOutpoint.ToString());
            return false;
        }

        if (pmn->IsNewStartRequired()) {
            LogPrint(BCLog::MN, "CMasternodePing::CheckAndUpdate -- masternode is completely expired, new start is required, masternode=%s\n", masternodeOutpoint.ToString());
            return false;
        }
    }

    {
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if ((*mi).second && (*mi).second->nHeight < chainActive.Height() - 24) {
            LogPrintf("CMasternodePing::CheckAndUpdate -- Masternode ping is invalid, block hash is too old: masternode=%s  blockHash=%s\n", masternodeOutpoint.ToString(), blockHash.ToString());
            // nDos = 1;
            return false;
        }
    }

    LogPrint(BCLog::MN, "CMasternodePing::CheckAndUpdate -- New ping: masternode=%s  blockHash=%s  sigTime=%d\n", masternodeOutpoint.ToString(), blockHash.ToString(), sigTime);

    // LogPrintf("mnping - Found corresponding mn for outpoint: %s\n", masternodeOutpoint.ToString());
    // update only if there is no known ping for this masternode or
    // last ping was more then MASTERNODE_MIN_MNP_SECONDS-60 ago comparing to this one
    if (pmn->IsPingedWithin(MASTERNODE_MIN_MNP_SECONDS - 60, sigTime)) {
        LogPrint(BCLog::MN, "CMasternodePing::CheckAndUpdate -- Masternode ping arrived too early, masternode=%s\n", masternodeOutpoint.ToString());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }

    if (!CheckSignature(pmn->pubKeyMasternode, nDos)) return false;

    // so, ping seems to be ok

    // if we are still syncing and there was no known ping for this mn for quite a while
    // (NOTE: assuming that MASTERNODE_EXPIRATION_SECONDS/2 should be enough to finish mn list sync)
    if(!masternodeSync.IsMasternodeListSynced() && !pmn->IsPingedWithin(MASTERNODE_EXPIRATION_SECONDS/2)) {
        // let's bump sync timeout
        LogPrint(BCLog::MN, "CMasternodePing::CheckAndUpdate -- bumping sync timeout, masternode=%s\n", masternodeOutpoint.ToString());
        masternodeSync.BumpAssetLastTime("CMasternodePing::CheckAndUpdate");
    }

    // let's store this ping as the last one
    LogPrint(BCLog::MN, "CMasternodePing::CheckAndUpdate -- Masternode ping accepted, masternode=%s\n", masternodeOutpoint.ToString());
    pmn->lastPing = *this;

    // and update mnodeman.mapSeenMasternodeBroadcast.lastPing which is probably outdated
    CMasternodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if (mnodeman.mapSeenMasternodeBroadcast.count(hash)) {
        mnodeman.mapSeenMasternodeBroadcast[hash].second.lastPing = *this;
    }

    // force update, ignoring cache
    pmn->Check(true);
    // relay ping for nodes in ENABLED/EXPIRED/SENTINEL_PING_EXPIRED state only, skip everyone else
    if (!pmn->IsEnabled() && !pmn->IsExpired() && !pmn->IsSentinelPingExpired()) return false;

//    LogPrint(BCLog::MN, "CMasternodePing::CheckAndUpdate -- Masternode ping acceepted and relayed, masternode=%s\n", masternodeOutpoint.ToString());
    Relay(connman);

    return true;
}

void CMasternodePing::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if(!masternodeSync.IsSynced()) {
        LogPrint(BCLog::MN, "CMasternodePing::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_MASTERNODE_PING, GetHash());
    connman.ForEachNode([&inv](CNode* pnode) {
        pnode->PushInventory(inv);
    });
}

// masternode-payments

/** Object for who's going to get paid on which blocks */
CMasternodePayments mnpayments;

CCriticalSection cs_vecPayees;
CCriticalSection cs_mapMasternodeBlocks;
CCriticalSection cs_mapMasternodePaymentVotes;

bool IsBlockPaymentsValid (const CTransaction& txNew, int nBlockHeight, CAmount blockReward) {
    if (!masternodeSync.IsSynced()) {
        //there is no budget data to use to check anything, let's just accept the longest chain
        return true;
    }
    // IF THIS ISN'T A SUPERBLOCK OR SUPERBLOCK IS INVALID, IT SHOULD PAY A MASTERNODE DIRECTLY
    if (mnpayments.IsTransactionValid(txNew, nBlockHeight)) {
        LogPrint(BCLog::MN, "IsBlockPaymentsValid -- Valid masternode payment at height %d: %s", nBlockHeight, txNew.ToString());
        return true;
    }
    LogPrintf("IsBlockPaymentsValid -- WARNING: Masternode payment enforcement is disabled, accepting any payee\n");
    return false;
}

void FillBlockPayments (CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward) {
    // FILL BLOCK PAYEE WITH MASTERNODE PAYMENT OTHERWISE
    CTxOut txoutMasternodeRet;
    mnpayments.FillBlockPayee(txNew, nBlockHeight, blockReward, txoutMasternodeRet);
    LogPrint(BCLog::MN, "FillBlockPayments -- nBlockHeight %d blockReward %lld txoutMasternodeRet %s txNew %s",
                            nBlockHeight, blockReward, txoutMasternodeRet.ToString(), CTransaction(txNew).ToString());
}

void CMasternodePayments::Clear()
{
    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);
    mapMasternodeBlocks.clear();
    mapMasternodePaymentVotes.clear();
}

bool CMasternodePayments::UpdateLastVote(const CMasternodePaymentVote& vote)
{
    LOCK(cs_mapMasternodePaymentVotes);

    const auto it = mapMasternodesLastVote.find(vote.masternodeOutpoint);
    if (it != mapMasternodesLastVote.end()) {
        if (it->second == vote.nBlockHeight)
            return false;
        it->second = vote.nBlockHeight;
        return true;
    }

    //record this masternode voted
    mapMasternodesLastVote.emplace(vote.masternodeOutpoint, vote.nBlockHeight);
    return true;
}

/**
*   FillBlockPayee
*
*   Fill Masternode ONLY payment block
*/

void CMasternodePayments::FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutMasternodeRet) const
{
    // make sure it's not filled yet
    txoutMasternodeRet = CTxOut();

    if (nBlockHeight < Params().GetConsensus().nMasternodePaymentsStartBlock) return;

    CScript payee;

    if(!GetBlockPayee(nBlockHeight, payee)) {
        // no masternode detected...
        int nCount = 0;
        CMasternodeBase mnInfo;
        if(!mnodeman.GetNextMasternodeInQueueForPayment(nBlockHeight, true, nCount, mnInfo)) {
            // ...and we can't calculate it on our own
            LogPrintf("CMasternodePayments::FillBlockPayee -- Failed to detect masternode to pay\n");
            return;
        }
        // fill payee with locally calculated winner and hope for the best
        payee = GetScriptForDestination(mnInfo.pubKeyCollateralAddress.GetID());
    }

    // GET MASTERNODE PAYMENT VARIABLES SETUP
    CAmount masternodePayment = (blockReward * Params().GetConsensus().nMasternodePaymentsPercent) / 100;

    // split reward between miner ...
    txNew.vout[0].nValue -= masternodePayment;
    // ... and masternode
    txoutMasternodeRet = CTxOut(masternodePayment, payee);
    txNew.vout.push_back(txoutMasternodeRet);

    LogPrintf("CMasternodePayments::FillBlockPayee -- Masternode payment %lld to %s\n", masternodePayment, script2addr(payee));
}

bool CMasternodePayments::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if (strCommand == NetMsgType::MASTERNODEPAYMENTSYNC) { //Masternode Payments Request Sync
        // Ignore such requests until we are fully synced.
        // We could start processing this after masternode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!masternodeSync.IsSynced()) return true;

        if(netfulfilledman.HasFulfilledRequest(pfrom->addr, NetMsgType::MASTERNODEPAYMENTSYNC)) {
            LOCK(cs_main);
            // Asking for the payments list multiple times in a short period of time is no good
            LogPrintf("MASTERNODEPAYMENTSYNC -- peer already asked me for the list, peer=%d\n", pfrom->GetId());
            Misbehaving(pfrom->GetId(), 20, "");
            return true;
        }
        netfulfilledman.AddFulfilledRequest(pfrom->addr, NetMsgType::MASTERNODEPAYMENTSYNC);

        Sync(pfrom, connman);
        LogPrintf("MASTERNODEPAYMENTSYNC -- Sent Masternode payment votes to peer=%d\n", pfrom->GetId());
        return true;
    } else if (strCommand == NetMsgType::MASTERNODEPAYMENTVOTE) { // Masternode Payments Vote for the Winner

        CMasternodePaymentVote vote;
        vRecv >> vote;

        uint256 nHash = vote.GetHash();

        pfrom->setAskFor.erase(nHash);

        // TODO: clear setAskFor for MSG_MASTERNODE_PAYMENT_BLOCK too

        // Ignore any payments messages until masternode list is synced
        if(!masternodeSync.IsMasternodeListSynced()) return true;

        {
            LOCK(cs_mapMasternodePaymentVotes);

            auto res = mapMasternodePaymentVotes.emplace(nHash, vote);

            // Avoid processing same vote multiple times if it was already verified earlier
            if(!res.second && res.first->second.IsVerified()) {
                LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTE -- hash=%s, nBlockHeight=%d/%d seen\n",
                            nHash.ToString(), vote.nBlockHeight, nCachedBlockHeight);
                return true;
            }

            // Mark vote as non-verified when it's seen for the first time,
            // AddOrUpdatePaymentVote() below should take care of it if vote is actually ok
            res.first->second.MarkAsNotVerified();
        }

        int nFirstBlock = nCachedBlockHeight - GetStorageLimit();
        if(vote.nBlockHeight < nFirstBlock || vote.nBlockHeight > nCachedBlockHeight+20) {
            LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTE -- vote out of range: nFirstBlock=%d, nBlockHeight=%d, nHeight=%d\n", nFirstBlock, vote.nBlockHeight, nCachedBlockHeight);
            return true;
        }

        std::string strError = "";
        if(!vote.IsValid(pfrom, nCachedBlockHeight, strError, connman)) {
            LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTE -- invalid message, error: %s\n", strError);
            return true;
        }

        CMasternodeBase mnInfo;
        if(!mnodeman.GetMasternodeInfo(vote.masternodeOutpoint, mnInfo)) {
            // mn was not found, so we can't check vote, some info is probably missing
            LogPrintf("MASTERNODEPAYMENTVOTE -- masternode is missing %s\n", vote.masternodeOutpoint.ToString());
            mnodeman.AskForMN(pfrom, vote.masternodeOutpoint, connman);
            return true;
        }

        int nDos = 0;
        if(!vote.CheckSignature(mnInfo.pubKeyMasternode, nCachedBlockHeight, nDos)) {
            if(nDos) {
                LOCK(cs_main);
                LogPrintf("MASTERNODEPAYMENTVOTE -- ERROR: invalid signature\n");
                Misbehaving(pfrom->GetId(), nDos, "");
            } else {
                // only warn about anything non-critical (i.e. nDos == 0) in debug mode
                LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTE -- WARNING: invalid signature\n");
            }
            // Either our info or vote info could be outdated.
            // In case our info is outdated, ask for an update,
            mnodeman.AskForMN(pfrom, vote.masternodeOutpoint, connman);
            // but there is nothing we can do if vote info itself is outdated
            // (i.e. it was signed by a mn which changed its key),
            // so just quit here.
            return true;
        }

        if(!UpdateLastVote(vote)) {
            LogPrintf("MASTERNODEPAYMENTVOTE -- masternode already voted, masternode=%s\n", vote.masternodeOutpoint.ToString());
            return true;
        }

        LogPrint(BCLog::MN, "MASTERNODEPAYMENTVOTE -- vote: address=%s, nBlockHeight=%d, nHeight=%d, prevout=%s, hash=%s new\n",
                script2addr(vote.payee), vote.nBlockHeight, nCachedBlockHeight, vote.masternodeOutpoint.ToString(), nHash.ToString());

        if(AddOrUpdatePaymentVote(vote)){
            vote.Relay(connman);
            masternodeSync.BumpAssetLastTime("MASTERNODEPAYMENTVOTE");
        }
        return true;
    }
    return false;
}

uint256 CMasternodePaymentVote::GetHash() const
{
    // Note: doesn't match serialization

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << *(CScriptBase*)(&payee);
    ss << nBlockHeight;
    ss << masternodeOutpoint;
    return ss.GetHash();
}

bool CMasternodePaymentVote::Sign()
{
    std::string strError;

    {
        std::string strMessage = masternodeOutpoint.ToString() +
                    boost::lexical_cast<std::string>(nBlockHeight) +
                    ScriptToAsmStr(payee);

        if(!CMessageSigner::SignMessage(strMessage, vchSig, activeMasternode.keyMasternode)) {
            LogPrintf("CMasternodePaymentVote::Sign -- SignMessage() failed\n");
            return false;
        }

        if(!CMessageSigner::VerifyMessage(activeMasternode.pubKeyMasternode, vchSig, strMessage, strError)) {
            LogPrintf("CMasternodePaymentVote::Sign -- VerifyMessage() failed, error: %s\n", strError);
            return false;
        }
    }

    return true;
}

bool CMasternodePayments::GetBlockPayee(int nBlockHeight, CScript& payeeRet) const
{
    LOCK(cs_mapMasternodeBlocks);

    auto it = mapMasternodeBlocks.find(nBlockHeight);
    return it != mapMasternodeBlocks.end() && it->second.GetBestPayee(payeeRet);
}

// Is this masternode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 blocks of votes
bool CMasternodePayments::IsScheduled(const CMasternodeBase& mnInfo, int nNotBlockHeight) const
{
    if (!masternodeSync.IsMasternodeListSynced()) return false;

    LOCK(cs_mapMasternodeBlocks);

    CScript mnpayee;
    mnpayee = GetScriptForDestination(mnInfo.pubKeyCollateralAddress.GetID());

    CScript payee;
    for(int64_t h = nCachedBlockHeight; h <= nCachedBlockHeight + 8; h++){
        if(h == nNotBlockHeight) continue;
        if(GetBlockPayee(h, payee) && mnpayee == payee) {
            return true;
        }
    }

    return false;
}

bool GetBlockHash(uint256& hashRet, int nBlockHeight) {
    LOCK(cs_main);
    if(chainActive.Tip() == nullptr) return false;
    if(nBlockHeight < -1 || nBlockHeight > chainActive.Height()) return false;
    if(nBlockHeight == -1) nBlockHeight = chainActive.Height();
    hashRet = chainActive[nBlockHeight]->GetBlockHash();
    return true;
}

bool CMasternodePayments::AddOrUpdatePaymentVote(const CMasternodePaymentVote& vote)
{
    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, vote.nBlockHeight - 101)) return false;

    uint256 nVoteHash = vote.GetHash();

    if(HasVerifiedPaymentVote(nVoteHash)) return false;

    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);

    mapMasternodePaymentVotes[nVoteHash] = vote;

    auto it = mapMasternodeBlocks.emplace(vote.nBlockHeight, CMasternodeBlockPayees(vote.nBlockHeight)).first;
    it->second.AddPayee(vote);

    LogPrint(BCLog::MN, "CMasternodePayments::AddOrUpdatePaymentVote -- added, hash=%s\n", nVoteHash.ToString());

    return true;
}

bool CMasternodePayments::HasVerifiedPaymentVote(const uint256& hashIn) const
{
    LOCK(cs_mapMasternodePaymentVotes);
    const auto it = mapMasternodePaymentVotes.find(hashIn);
    return it != mapMasternodePaymentVotes.end() && it->second.IsVerified();
}

void CMasternodeBlockPayees::AddPayee(const CMasternodePaymentVote& vote)
{
    LOCK(cs_vecPayees);

    uint256 nVoteHash = vote.GetHash();

    for (auto& payee : vecPayees) {
        if (payee.GetPayee() == vote.payee) {
            payee.AddVoteHash(nVoteHash);
            return;
        }
    }
    CMasternodePayee payeeNew(vote.payee, nVoteHash);
    vecPayees.push_back(payeeNew);
}

bool CMasternodeBlockPayees::GetBestPayee(CScript& payeeRet) const
{
    LOCK(cs_vecPayees);

    if(vecPayees.empty()) {
        LogPrint(BCLog::MN, "CMasternodeBlockPayees::GetBestPayee -- ERROR: couldn't find any payee\n");
        return false;
    }

    int nVotes = -1;
    for (const auto& payee : vecPayees) {
        if (payee.GetVoteCount() > nVotes) {
            payeeRet = payee.GetPayee();
            nVotes = payee.GetVoteCount();
        }
    }

    return nVotes >= 0;
}

bool CMasternodeBlockPayees::HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq) const
{
    LOCK(cs_vecPayees);

    for (const auto& payee : vecPayees) {
        if (payee.GetVoteCount() >= nVotesReq && payee.GetPayee() == payeeIn) {
            return true;
        }
    }

//    LogPrint(BCLog::MN, "CMasternodeBlockPayees::HasPayeeWithVotes -- ERROR: couldn't find any payee with %d+ votes\n", nVotesReq);
    return false;
}

bool CMasternodeBlockPayees::IsTransactionValid(const CTransaction& txNew) const
{
    LOCK(cs_vecPayees);

    int nMaxSignatures = 0;
    std::string strPayeesPossible = "";

    CAmount nMasternodePayment = (txNew.GetValueOut() * Params().GetConsensus().nMasternodePaymentsPercent) / 100;

    //require at least MNPAYMENTS_SIGNATURES_REQUIRED signatures

    for (const auto& payee : vecPayees) {
        if (payee.GetVoteCount() >= nMaxSignatures) {
            nMaxSignatures = payee.GetVoteCount();
        }
    }

    // if we don't have at least MNPAYMENTS_SIGNATURES_REQUIRED signatures on a payee, approve whichever is the longest chain
    if(nMaxSignatures < MNPAYMENTS_SIGNATURES_REQUIRED) return true;

    for (const auto& payee : vecPayees) {
        if (payee.GetVoteCount() >= MNPAYMENTS_SIGNATURES_REQUIRED) {
            for (const auto& txout : txNew.vout) {
                if (payee.GetPayee() == txout.scriptPubKey && nMasternodePayment == txout.nValue) {
                    LogPrint(BCLog::MN, "CMasternodeBlockPayees::IsTransactionValid -- Found required payment\n");
                    return true;
                }
            }

            if(strPayeesPossible == "") {
                strPayeesPossible = script2addr(payee.GetPayee());
            } else {
                strPayeesPossible += "," + script2addr(payee.GetPayee());
            }
        }
    }

    LogPrintf("CMasternodeBlockPayees::IsTransactionValid -- ERROR: Missing required payment, possible payees: '%s', amount: %f DASH\n", strPayeesPossible, (float)nMasternodePayment/COIN);
    return false;
}

std::string CMasternodeBlockPayees::GetRequiredPaymentsString() const
{
    LOCK(cs_vecPayees);

    std::string strRequiredPayments = "";

    for (const auto& payee : vecPayees)
    {
        if (!strRequiredPayments.empty())
            strRequiredPayments += ", ";

        strRequiredPayments += strprintf("%s:%d", script2addr(payee.GetPayee()), payee.GetVoteCount());
    }

    if (strRequiredPayments.empty())
        return "Unknown";

    return strRequiredPayments;
}

std::string CMasternodePayments::GetRequiredPaymentsString(int nBlockHeight) const
{
    LOCK(cs_mapMasternodeBlocks);

    const auto it = mapMasternodeBlocks.find(nBlockHeight);
    return it == mapMasternodeBlocks.end() ? "Unknown" : it->second.GetRequiredPaymentsString();
}

bool CMasternodePayments::IsTransactionValid(const CTransaction& txNew, int nBlockHeight) const
{
    if (nBlockHeight < Params().GetConsensus().nMasternodePaymentsStartBlock) return true;

    LOCK(cs_mapMasternodeBlocks);

    const auto it = mapMasternodeBlocks.find(nBlockHeight);
    return it == mapMasternodeBlocks.end() ? true : it->second.IsTransactionValid(txNew);
}

void CMasternodePayments::CheckAndRemove()
{
    if(!masternodeSync.IsBlockchainSynced()) return;

    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);

    int nLimit = GetStorageLimit();

    std::map<uint256, CMasternodePaymentVote>::iterator it = mapMasternodePaymentVotes.begin();
    while(it != mapMasternodePaymentVotes.end()) {
        CMasternodePaymentVote vote = (*it).second;

        if(nCachedBlockHeight - vote.nBlockHeight > nLimit) {
            LogPrint(BCLog::MN, "CMasternodePayments::CheckAndRemove -- Removing old Masternode payment: nBlockHeight=%d\n", vote.nBlockHeight);
            mapMasternodePaymentVotes.erase(it++);
            mapMasternodeBlocks.erase(vote.nBlockHeight);
        } else {
            ++it;
        }
    }
    LogPrint(BCLog::MN, "CMasternodePayments::CheckAndRemove -- %s\n", ToString());
}

bool CMasternodePaymentVote::IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman) const
{
    CMasternodeBase mnInfo;

    if(!mnodeman.GetMasternodeInfo(masternodeOutpoint, mnInfo)) {
        strError = strprintf("Unknown masternode=%s", masternodeOutpoint.ToString());
        // Only ask if we are already synced and still have no idea about that Masternode
        if(masternodeSync.IsMasternodeListSynced()) {
            mnodeman.AskForMN(pnode, masternodeOutpoint, connman);
        }

        return false;
    }

    // Only masternodes should try to check masternode rank for old votes - they need to pick the right winner for future blocks.
    // Regular clients (miners included) need to verify masternode rank for future block votes only.
    if(!fMasternodeMode && nBlockHeight < nValidationHeight) return true;

    int nRank;

    if(!mnodeman.GetMasternodeRank(masternodeOutpoint, nRank, nBlockHeight - 101, 0)) {
        LogPrint(BCLog::MN, "CMasternodePaymentVote::IsValid -- Can't calculate rank for masternode %s\n",
                    masternodeOutpoint.ToString());
        return false;
    }

    if(nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        // It's common to have masternodes mistakenly think they are in the top 10
        // We don't want to print all of these messages in normal mode, debug mode should print though
        strError = strprintf("Masternode %s is not in the top %d (%d)", masternodeOutpoint.ToString(), MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        // Only ban for new mnw which is out of bounds, for old mnw MN list itself might be way too much off
        if(nRank > MNPAYMENTS_SIGNATURES_TOTAL*2 && nBlockHeight > nValidationHeight) {
            LOCK(cs_main);
            strError = strprintf("Masternode %s is not in the top %d (%d)", masternodeOutpoint.ToString(), MNPAYMENTS_SIGNATURES_TOTAL*2, nRank);
            LogPrintf("CMasternodePaymentVote::IsValid -- Error: %s\n", strError);
            Misbehaving(pnode->GetId(), 20, "");
        }
        // Still invalid however
        return false;
    }

    return true;
}

bool CMasternodePayments::ProcessBlock(int nBlockHeight, CConnman& connman)
{
    // DETERMINE IF WE SHOULD BE VOTING FOR THE NEXT PAYEE

    if(!fMasternodeMode) return false;

    // We have little chances to pick the right winner if winners list is out of sync
    // but we have no choice, so we'll try. However it doesn't make sense to even try to do so
    // if we have not enough data about masternodes.
    if(!masternodeSync.IsMasternodeListSynced()) return false;

    int nRank;

    if (!mnodeman.GetMasternodeRank(activeMasternode.outpoint, nRank, nBlockHeight - 101, 0)) {
        LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- Unknown Masternode\n");
        return false;
    }

    if (nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- Masternode not in the top %d (%d)\n", MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        return false;
    }


    // LOCATE THE NEXT MASTERNODE WHICH SHOULD BE PAID

    LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- Start: nBlockHeight=%d, masternode=%s\n", nBlockHeight, activeMasternode.outpoint.ToString());

    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    int nCount = 0;
    CMasternodeBase mnInfo;

    if (!mnodeman.GetNextMasternodeInQueueForPayment(nBlockHeight, true, nCount, mnInfo)) {
        LogPrintf("CMasternodePayments::ProcessBlock -- ERROR: Failed to find masternode to pay\n");
        return false;
    }

    LogPrint(BCLog::MN, "CMasternodePayments::ProcessBlock -- Masternode found by GetNextMasternodeInQueueForPayment(): %s\n", mnInfo.outpoint.ToString());


    CScript payee = GetScriptForDestination(mnInfo.pubKeyCollateralAddress.GetID());

    CMasternodePaymentVote voteNew(activeMasternode.outpoint, nBlockHeight, payee);

    LogPrintf("CMasternodePayments::ProcessBlock -- vote: payee=%s, nBlockHeight=%d\n", script2addr(payee), nBlockHeight);

    // SIGN MESSAGE TO NETWORK WITH OUR MASTERNODE KEYS

    LogPrintf("CMasternodePayments::ProcessBlock -- Signing vote\n");
    if (voteNew.Sign()) {
        LogPrintf("CMasternodePayments::ProcessBlock -- AddOrUpdatePaymentVote()\n");

        if (AddOrUpdatePaymentVote(voteNew)) {
            voteNew.Relay(connman);
            return true;
        }
    }

    return false;
}

void CMasternodePayments::CheckBlockVotes(int nBlockHeight)
{
    if (!masternodeSync.IsWinnersListSynced()) return;

    CMasternodeMan::rank_pair_vec_t mns;
    if (!mnodeman.GetMasternodeRanks(mns, nBlockHeight - 101, 0)) {
        LogPrintf("CMasternodePayments::CheckBlockVotes -- nBlockHeight=%d, GetMasternodeRanks failed\n", nBlockHeight);
        return;
    }

    std::string debugStr;

    debugStr += strprintf("CMasternodePayments::CheckBlockVotes -- nBlockHeight=%d,\n  Expected voting MNs:\n", nBlockHeight);

    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);

    int i{0};
    for (const auto& mn : mns) {
        CScript payee;
        bool found = false;

        const auto it = mapMasternodeBlocks.find(nBlockHeight);
        if (it != mapMasternodeBlocks.end()) {
            for (const auto& p : it->second.vecPayees) {
                for (const auto& voteHash : p.GetVoteHashes()) {
                    const auto itVote = mapMasternodePaymentVotes.find(voteHash);
                    if (itVote == mapMasternodePaymentVotes.end()) {
                        debugStr += strprintf("    - could not find vote %s\n",
                                              voteHash.ToString());
                        continue;
                    }
                    if (itVote->second.masternodeOutpoint == mn.second.outpoint) {
                        payee = itVote->second.payee;
                        found = true;
                        break;
                    }
                }
            }
        }

        if (found) {
            debugStr += strprintf("    - %s - voted for %s\n",
                                  mn.second.outpoint.ToString(), script2addr(payee));
        } else {
            mapMasternodesDidNotVote.emplace(mn.second.outpoint, 0).first->second++;

            debugStr += strprintf("    - %s - no vote received\n",
                                  mn.second.outpoint.ToString());
        }

        if (++i >= MNPAYMENTS_SIGNATURES_TOTAL) break;
    }

    if (mapMasternodesDidNotVote.empty()) {
        LogPrint(BCLog::MN, "%s", debugStr);
        return;
    }

    debugStr += "  Masternodes which missed a vote in the past:\n";
    for (const auto& item : mapMasternodesDidNotVote) {
        debugStr += strprintf("    - %s: %d\n", item.first.ToString(), item.second);
    }

    LogPrint(BCLog::MN, "%s", debugStr);
}

void CMasternodePaymentVote::Relay(CConnman& connman) const
{
    // Do not relay until fully synced
    if(!masternodeSync.IsSynced()) {
        LogPrint(BCLog::MN, "CMasternodePayments::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_MASTERNODE_PAYMENT_VOTE, GetHash());
    connman.ForEachNode([&inv](CNode* pnode) {
        pnode->PushInventory(inv);
    });
}

bool CMasternodePaymentVote::CheckSignature(const CPubKey& pubKeyMasternode, int nValidationHeight, int &nDos) const
{
    // do not ban by default
    nDos = 0;
    std::string strError = "";

    {
        std::string strMessage = masternodeOutpoint.ToString() +
                    boost::lexical_cast<std::string>(nBlockHeight) +
                    ScriptToAsmStr(payee);

        if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
            // Only ban for future block vote when we are already synced.
            // Otherwise it could be the case when MN which signed this vote is using another key now
            // and we have no idea about the old one.
            if(masternodeSync.IsMasternodeListSynced() && nBlockHeight > nValidationHeight) {
                nDos = 20;
            }
            return error("CMasternodePaymentVote::CheckSignature -- Got bad Masternode payment signature, masternode=%s, error: %s",
                        masternodeOutpoint.ToString(), strError);
        }
    }

    return true;
}

std::string CMasternodePaymentVote::ToString() const
{
    std::ostringstream info;

    info << masternodeOutpoint.ToString() <<
            ", " << nBlockHeight <<
            ", " << script2addr(payee) <<
            ", " << (int)vchSig.size();

    return info.str();
}

// Send only votes for future blocks, node should request every other missing payment block individually
void CMasternodePayments::Sync(CNode* pnode, CConnman& connman) const
{
    LOCK(cs_mapMasternodeBlocks);

    if(!masternodeSync.IsWinnersListSynced()) return;

    int nInvCount = 0;

    for(int h = nCachedBlockHeight; h < nCachedBlockHeight + 20; h++) {
        const auto it = mapMasternodeBlocks.find(h);
        if(it != mapMasternodeBlocks.end()) {
            for (const auto& payee : it->second.vecPayees) {
                std::vector<uint256> vecVoteHashes = payee.GetVoteHashes();
                for (const auto& hash : vecVoteHashes) {
                    if(!HasVerifiedPaymentVote(hash)) continue;
                    pnode->PushInventory(CInv(MSG_MASTERNODE_PAYMENT_VOTE, hash));
                    nInvCount++;
                }
            }
        }
    }

    LogPrintf("CMasternodePayments::Sync -- Sent %d votes to peer=%d\n", nInvCount, pnode->GetId());
    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_MNW, nInvCount));
}

// Request low data/unknown payment blocks in batches directly from some node instead of/after preliminary Sync.
void CMasternodePayments::RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman) const
{
    if(!masternodeSync.IsMasternodeListSynced()) return;

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    LOCK2(cs_main, cs_mapMasternodeBlocks);

    std::vector<CInv> vToFetch;
    int nLimit = GetStorageLimit();

    const CBlockIndex *pindex = chainActive.Tip();

    while(nCachedBlockHeight - pindex->nHeight < nLimit) {
        const auto it = mapMasternodeBlocks.find(pindex->nHeight);
        if(it == mapMasternodeBlocks.end()) {
            // We have no idea about this block height, let's ask
            vToFetch.push_back(CInv(MSG_MASTERNODE_PAYMENT_BLOCK, pindex->GetBlockHash()));
            // We should not violate GETDATA rules
            if(vToFetch.size() == MAX_INV_SZ) {
                LogPrintf("CMasternodePayments::RequestLowDataPaymentBlocks -- asking peer=%d for %d blocks\n", pnode->GetId(), MAX_INV_SZ);
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
                // Start filling new batch
                vToFetch.clear();
            }
        }
        if(!pindex->pprev) break;
        pindex = pindex->pprev;
    }

    auto it = mapMasternodeBlocks.begin();

    while(it != mapMasternodeBlocks.end()) {
        int nTotalVotes = 0;
        bool fFound = false;
        for (const auto& payee : it->second.vecPayees) {
            if(payee.GetVoteCount() >= MNPAYMENTS_SIGNATURES_REQUIRED) {
                fFound = true;
                break;
            }
            nTotalVotes += payee.GetVoteCount();
        }
        // A clear winner (MNPAYMENTS_SIGNATURES_REQUIRED+ votes) was found
        // or no clear winner was found but there are at least avg number of votes
        if(fFound || nTotalVotes >= (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED)/2) {
            // so just move to the next block
            ++it;
            continue;
        }
        // Low data block found, let's try to sync it
        uint256 hash;
        if(GetBlockHash(hash, it->first)) {
            vToFetch.push_back(CInv(MSG_MASTERNODE_PAYMENT_BLOCK, hash));
        }
        // We should not violate GETDATA rules
        if(vToFetch.size() == MAX_INV_SZ) {
            LogPrintf("CMasternodePayments::RequestLowDataPaymentBlocks -- asking peer=%d for %d payment blocks\n", pnode->GetId(), MAX_INV_SZ);
            connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
            // Start filling new batch
            vToFetch.clear();
        }
        ++it;
    }
    // Ask for the rest of it
    if(!vToFetch.empty()) {
        LogPrintf("CMasternodePayments::RequestLowDataPaymentBlocks -- asking peer=%d for %d payment blocks\n", pnode->GetId(), vToFetch.size());
        connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
    }
}

std::string CMasternodePayments::ToString() const
{
    std::ostringstream info;

    info << "Votes: " << (int)mapMasternodePaymentVotes.size() <<
            ", Blocks: " << (int)mapMasternodeBlocks.size();

    return info.str();
}

bool CMasternodePayments::IsEnoughData() const
{
    float nAverageVotes = (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED) / 2;
    int nStorageLimit = GetStorageLimit();
    return GetBlockCount() > nStorageLimit && GetVoteCount() > nStorageLimit * nAverageVotes;
}

int CMasternodePayments::GetStorageLimit() const
{
    return std::max(int(mnodeman.size() * nStorageCoeff), nMinBlocksToStore);
}

void CMasternodePayments::UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman)
{
    if(!pindex) return;

    nCachedBlockHeight = pindex->nHeight;
    LogPrint(BCLog::MN, "CMasternodePayments::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    int nFutureBlock = nCachedBlockHeight + 10;

    CheckBlockVotes(nFutureBlock - 1);
    ProcessBlock(nFutureBlock, connman);
} 

void CMasternodePayments::Dump (const std::string& border, std::function<void(std::string)> dumpfunc) {
    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);     
    dumpfunc (border + "CMasternodePayments {");
    dumpfunc (border + "    mapMasternodePaymentVotes {");
    for (auto& item : mapMasternodePaymentVotes)
        dumpfunc (border + "        " + HexStr(item.first) + " - " + item.second.ToString());
    dumpfunc (border + "    }");
    dumpfunc ("");
    dumpfunc (border + "    mapMasternodeBlocks {");
    for (auto& item : mapMasternodeBlocks) {
        dumpfunc (border + "        " + itostr(item.first) + " {");
        {//for (auto& item2 : item.second) {       // CMasternodeBlockPayees
            dumpfunc (border + "            " + itostr(item.second.nBlockHeight) + " {");
            for (auto& item3 : item.second.vecPayees) {       // CMasternodePayee
                dumpfunc (border + "                " + script2addr(item3.GetPayee()) + " {");
                for (auto& item4 : item3.GetVoteHashes()) {
                    dumpfunc (border + "                    " + HexStr(item4));
                }
                dumpfunc (border + "                }");
            }
            dumpfunc (border + "            }");
        }
        dumpfunc (border + "        }");
    }
    dumpfunc (border + "    }");
    dumpfunc ("");
    dumpfunc (border + "    mapMasternodesLastVote {");
    for (auto& item : mapMasternodesLastVote)
        dumpfunc (border + "        " + item.first.ToString() + " - " + itostr(item.second));
    dumpfunc (border + "    }");
    dumpfunc ("");
    dumpfunc (border + "    mapMasternodesDidNotVote {");
    for (auto& item : mapMasternodesDidNotVote)
        dumpfunc (border + "        " + item.first.ToString() + " - " + itostr(item.second));
    dumpfunc (border + "    }");
    dumpfunc (border + "}");
}

// masternode-sync

CMasternodeSync masternodeSync;

void CMasternodeSync::Fail()
{
    nTimeLastFailure = GetTime();
    nRequestedMasternodeAssets = MASTERNODE_SYNC_FAILED;
}

void CMasternodeSync::Reset()
{
    nRequestedMasternodeAssets = MASTERNODE_SYNC_INITIAL;
    nRequestedMasternodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastBumped = GetTime();
    nTimeLastFailure = 0;
}

void CMasternodeSync::BumpAssetLastTime(const std::string& strFuncName)
{
    if(IsSynced() || IsFailed()) return;
    nTimeLastBumped = GetTime();
    LogPrint(BCLog::MN, "CMasternodeSync::BumpAssetLastTime -- %s\n", strFuncName);
}

std::string CMasternodeSync::GetAssetName()
{
    switch(nRequestedMasternodeAssets)
    {
        case(MASTERNODE_SYNC_INITIAL):      return "MASTERNODE_SYNC_INITIAL";
        case(MASTERNODE_SYNC_WAITING):      return "MASTERNODE_SYNC_WAITING";
        case(MASTERNODE_SYNC_LIST):         return "MASTERNODE_SYNC_LIST";
        case(MASTERNODE_SYNC_MNW):          return "MASTERNODE_SYNC_MNW";
        case(MASTERNODE_SYNC_GOVERNANCE):   return "MASTERNODE_SYNC_GOVERNANCE";
        case(MASTERNODE_SYNC_FAILED):       return "MASTERNODE_SYNC_FAILED";
        case MASTERNODE_SYNC_FINISHED:      return "MASTERNODE_SYNC_FINISHED";
        default:                            return "UNKNOWN";
    }
}

void CMasternodeSync::SwitchToNextAsset(CConnman& connman)
{
    switch(nRequestedMasternodeAssets)
    {
        case(MASTERNODE_SYNC_FAILED):
            throw std::runtime_error("Can't switch to next asset from failed, should use Reset() first!");
            break;
        case(MASTERNODE_SYNC_INITIAL):
            nRequestedMasternodeAssets = MASTERNODE_SYNC_WAITING;
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(MASTERNODE_SYNC_WAITING):
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedMasternodeAssets = MASTERNODE_SYNC_LIST;
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(MASTERNODE_SYNC_LIST):
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedMasternodeAssets = MASTERNODE_SYNC_MNW;
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(MASTERNODE_SYNC_MNW):
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedMasternodeAssets = MASTERNODE_SYNC_GOVERNANCE;
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(MASTERNODE_SYNC_GOVERNANCE):
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedMasternodeAssets = MASTERNODE_SYNC_FINISHED;
            uiInterface.NotifyAdditionalDataSyncProgressChanged(100);
            //try to activate our masternode if possible
            activeMasternode.ManageState(connman);

            connman.ForEachNode([](CNode* pnode) {
                netfulfilledman.AddFulfilledRequest(pnode->addr, "full-sync");
            });
            LogPrintf("CMasternodeSync::SwitchToNextAsset -- Sync has finished\n");

            break;
    }
    nRequestedMasternodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    BumpAssetLastTime("CMasternodeSync::SwitchToNextAsset");
}

std::string CMasternodeSync::GetSyncStatus()
{
    switch (masternodeSync.nRequestedMasternodeAssets) {
        case MASTERNODE_SYNC_INITIAL:       return _("Synchroning blockchain...");
        case MASTERNODE_SYNC_WAITING:       return _("Synchronization pending...");
        case MASTERNODE_SYNC_LIST:          return _("Synchronizing masternodes...");
        case MASTERNODE_SYNC_MNW:           return _("Synchronizing masternode payments...");
        case MASTERNODE_SYNC_GOVERNANCE:    return _("Synchronizing governance objects...");
        case MASTERNODE_SYNC_FAILED:        return _("Synchronization failed");
        case MASTERNODE_SYNC_FINISHED:      return _("Synchronization finished");
        default:                            return "";
    }
}

bool CMasternodeSync::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == NetMsgType::SYNCSTATUSCOUNT) { //Sync status count

        //do not care about stats if sync process finished or failed
        if(IsSynced() || IsFailed()) return true;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        LogPrintf("SYNCSTATUSCOUNT -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->GetId());
        return true;
    }
    return false;
}

void CMasternodeSync::ProcessTick(CConnman& connman)
{
    static int nTick = 0;
    if(nTick++ % MASTERNODE_SYNC_TICK_SECONDS != 0) return;

    // reset the sync process if the last call to this function was more than 60 minutes ago (client was in sleep mode)
    static int64_t nTimeLastProcess = GetTime();
    if(GetTime() - nTimeLastProcess > 60*60) {
        LogPrintf("CMasternodeSync::ProcessTick -- WARNING: no actions for too long, restarting sync...\n");
        Reset();
        SwitchToNextAsset(connman);
        nTimeLastProcess = GetTime();
        return;
    }
    nTimeLastProcess = GetTime();

    // reset sync status in case of any other sync failure
    if(IsFailed()) {
        if(nTimeLastFailure + (1*60) < GetTime()) { // 1 minute cooldown after failed sync
            LogPrintf("CMasternodeSync::ProcessTick -- WARNING: failed to sync, trying again...\n");
            Reset();
            SwitchToNextAsset(connman);
        }
        return;
    }

    // gradually request the rest of the votes after sync finished
    if(IsSynced()) {
        return;
    }

    // Calculate "progress" for LOG reporting / GUI notification
    double nSyncProgress = double(nRequestedMasternodeAttempt + (nRequestedMasternodeAssets - 1) * 8) / (8*4);
    LogPrintf("CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d nRequestedMasternodeAttempt %d nSyncProgress %f\n", nTick, nRequestedMasternodeAssets, nRequestedMasternodeAttempt, nSyncProgress);
    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress*100);

    std::vector<CNode*> vNodesCopy = connman.CopyNodeVector();

    for (auto& pnode : vNodesCopy)
    {
        if (!(pnode && pnode->fSuccessfullyConnected && !pnode->fDisconnect)) continue;

        CNetMsgMaker msgMaker(pnode->GetSendVersion());

        // Don't try to sync any data from outbound "masternode" connections -
        // they are temporary and should be considered unreliable for a sync process.
        // Inbound connection this early is most likely a "masternode" connection
        // initiated from another node, so skip it too.
        if(pnode->fMasternode || (fMasternodeMode && pnode->fInbound)) continue;

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if(netfulfilledman.HasFulfilledRequest(pnode->addr, "full-sync")) {
                // We already fully synced from this node recently,
              // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                LogPrintf("CMasternodeSync::ProcessTick -- disconnecting from recently synced peer=%d\n", pnode->GetId());
                continue;
            }

            // INITIAL TIMEOUT

            if(nRequestedMasternodeAssets == MASTERNODE_SYNC_WAITING) {
                if(GetTime() - nTimeLastBumped > MASTERNODE_SYNC_TIMEOUT_SECONDS) {
                    // At this point we know that:
                    // a) there are peers (because we are looping on at least one of them);
                    // b) we waited for at least MASTERNODE_SYNC_TIMEOUT_SECONDS since we reached
                    //    the headers tip the last time (i.e. since we switched from
                    //     MASTERNODE_SYNC_INITIAL to MASTERNODE_SYNC_WAITING and bumped time);
                    // c) there were no blocks (UpdatedBlockTip, NotifyHeaderTip) or headers (AcceptedBlockHeader)
                    //    for at least MASTERNODE_SYNC_TIMEOUT_SECONDS.
                    // We must be at the tip already, let's move to the next asset.
                    SwitchToNextAsset(connman);
                }
            }

            // MNLIST : SYNC MASTERNODE LIST FROM OTHER CONNECTED CLIENTS

            if(nRequestedMasternodeAssets == MASTERNODE_SYNC_LIST) {
                LogPrint(BCLog::MN, "CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedMasternodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);
                // check for timeout first
                if (GetTime() - nTimeLastBumped > MASTERNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d -- timeout\n", nTick, nRequestedMasternodeAssets);
                    if (nRequestedMasternodeAttempt == 0) {
                        LogPrintf("CMasternodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // there is no way we can continue without masternode list, fail here and try later
                        Fail();
                        connman.ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // request from three peers max
                if (nRequestedMasternodeAttempt > 2) {
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if(netfulfilledman.HasFulfilledRequest(pnode->addr, "masternode-list-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "masternode-list-sync");

                nRequestedMasternodeAttempt++;

                mnodeman.DsegUpdate(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // MNW : SYNC MASTERNODE PAYMENT VOTES FROM OTHER CONNECTED CLIENTS

            if(nRequestedMasternodeAssets == MASTERNODE_SYNC_MNW) {
                LogPrint(BCLog::MN, "CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedMasternodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);
                // check for timeout first
                // This might take a lot longer than MASTERNODE_SYNC_TIMEOUT_SECONDS due to new blocks,
                // but that should be OK and it should timeout eventually.
                if(GetTime() - nTimeLastBumped > MASTERNODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrintf("CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d -- timeout\n", nTick, nRequestedMasternodeAssets);
                    if (nRequestedMasternodeAttempt == 0) {
                        LogPrintf("CMasternodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // probably not a good idea to proceed without winner list
                        Fail();
                        connman.ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // check for data
                // if mnpayments already has enough blocks and votes, switch to the next asset
                // try to fetch data from at least two peers though
                if(nRequestedMasternodeAttempt > 1 && mnpayments.IsEnoughData()) {
                    LogPrintf("CMasternodeSync::ProcessTick -- nTick %d nRequestedMasternodeAssets %d -- found enough data\n", nTick, nRequestedMasternodeAssets);
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // request from three peers max
                if (nRequestedMasternodeAttempt > 2) {
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if(netfulfilledman.HasFulfilledRequest(pnode->addr, "masternode-payment-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "masternode-payment-sync");
                nRequestedMasternodeAttempt++;

                // ask node for all payment votes it has (new nodes will only return votes for future payments)
                //sync payment votes
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::MASTERNODEPAYMENTSYNC));
                // ask node for missing pieces only (old nodes will not be asked)
                mnpayments.RequestLowDataPaymentBlocks(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // GOVOBJ : SYNC GOVERNANCE ITEMS FROM OUR PEERS

            if(nRequestedMasternodeAssets == MASTERNODE_SYNC_GOVERNANCE) {
                SwitchToNextAsset(connman);
                connman.ReleaseNodeVector(vNodesCopy);
                return;
            }
        }
    }
    // looped through all nodes, release them
    connman.ReleaseNodeVector(vNodesCopy);
}

void CMasternodeSync::NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint(BCLog::MN, "CMasternodeSync::NotifyHeaderTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::NotifyHeaderTip");
    }
}

void CMasternodeSync::UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint(BCLog::MN, "CMasternodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CMasternodeSync::UpdatedBlockTip");
    }

    if (fInitialDownload) {
        // switched too early
        if (IsBlockchainSynced()) {
            Reset();
        }

        // no need to check any further while still in IBD mode
        return;
    }

    // Note: since we sync headers first, it should be ok to use this
    static bool fReachedBestHeader = false;
    bool fReachedBestHeaderNew = pindexNew->GetBlockHash() == pindexBestHeader->GetBlockHash();

    if (fReachedBestHeader && !fReachedBestHeaderNew) {
        // Switching from true to false means that we previousely stuck syncing headers for some reason,
        // probably initial timeout was not enough,
        // because there is no way we can update tip not having best header
        Reset();
        fReachedBestHeader = false;
        return;
    }

    fReachedBestHeader = fReachedBestHeaderNew;

    LogPrint(BCLog::MN, "CMasternodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d pindexBestHeader->nHeight: %d fInitialDownload=%d fReachedBestHeader=%d\n",
                pindexNew->nHeight, pindexBestHeader->nHeight, fInitialDownload, fReachedBestHeader);

    if (!IsBlockchainSynced() && fReachedBestHeader) {
        // Reached best header while being in initial mode.
        // We must be at the tip already, let's move to the next asset.
        SwitchToNextAsset(connman);
    }
}

// masternodeman

/** Masternode manager */
CMasternodeMan mnodeman;

const std::string CMasternodeMan::SERIALIZATION_VERSION_STRING = "CMasternodeMan-Version-8";
const int CMasternodeMan::LAST_PAID_SCAN_BLOCKS = 100;

struct CompareLastPaidBlock
{
    bool operator()(const std::pair<int, const CMasternode*>& t1,
                    const std::pair<int, const CMasternode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->outpoint < t2.second->outpoint);
    }
};

struct CompareScoreMN
{
    bool operator()(const std::pair<arith_uint256, const CMasternode*>& t1,
                    const std::pair<arith_uint256, const CMasternode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->outpoint < t2.second->outpoint);
    }
};

struct CompareByAddr

{
    bool operator()(const CMasternode* t1,
                    const CMasternode* t2) const
    {
        return t1->addr < t2->addr;
    }
};

CMasternodeMan::CMasternodeMan():
    cs(),
    mapMasternodes(),
    mAskedUsForMasternodeList(),
    mWeAskedForMasternodeList(),
    mWeAskedForMasternodeListEntry(),
    mWeAskedForVerification(),
    mMnbRecoveryRequests(),
    mMnbRecoveryGoodReplies(),
    listScheduledMnbRequestConnections(),
    fMasternodesAdded(false),
    fMasternodesRemoved(false),
    nLastSentinelPingTime(0),
    mapSeenMasternodeBroadcast(),
    mapSeenMasternodePing(),
    nDsqCount(0)
{}

bool CMasternodeMan::Add(CMasternode &mn)
{
    LOCK(cs);

    if (Has(mn.outpoint)) return false;

    LogPrint(BCLog::MN, "CMasternodeMan::Add -- Adding new Masternode: addr=%s, %i now\n", mn.addr.ToString(), size() + 1);
    mapMasternodes[mn.outpoint] = mn;
    fMasternodesAdded = true;
    return true;
}

void CMasternodeMan::AskForMN(CNode* pnode, const COutPoint& outpoint, CConnman& connman)
{
    if(!pnode) return;

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    LOCK(cs);

    CService addrSquashed = (CService)pnode->addr;
    auto it1 = mWeAskedForMasternodeListEntry.find(outpoint);
    if (it1 != mWeAskedForMasternodeListEntry.end()) {
        auto it2 = it1->second.find(addrSquashed);
        if (it2 != it1->second.end()) {
            if (GetTime() < it2->second) {
                // we've asked recently, should not repeat too often or we could get banned
                return;
            }
            // we asked this node for this outpoint but it's ok to ask again already
            LogPrintf("CMasternodeMan::AskForMN -- Asking same peer %s for missing masternode entry again: %s\n", addrSquashed.ToString(), outpoint.ToString());
        } else {
            // we already asked for this outpoint but not this node
            LogPrintf("CMasternodeMan::AskForMN -- Asking new peer %s for missing masternode entry: %s\n", addrSquashed.ToString(), outpoint.ToString());
        }
    } else {
        // we never asked any node for this outpoint
        LogPrintf("CMasternodeMan::AskForMN -- Asking peer %s for missing masternode entry for the first time: %s\n", addrSquashed.ToString(), outpoint.ToString());
    }
    mWeAskedForMasternodeListEntry[outpoint][addrSquashed] = GetTime() + DSEG_UPDATE_SECONDS;

    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::DSEG, outpoint));
}

bool CMasternodeMan::AllowMixing(const COutPoint &outpoint)
{
    LOCK(cs);
    CMasternode* pmn = Find(outpoint);
    if (!pmn) {
        return false;
    }
    nDsqCount++;
    pmn->nLastDsq = nDsqCount;
    pmn->fAllowMixingTx = true;

    return true;
}

bool CMasternodeMan::DisallowMixing(const COutPoint &outpoint)
{
    LOCK(cs);
    CMasternode* pmn = Find(outpoint);
    if (!pmn) {
        return false;
    }
    pmn->fAllowMixingTx = false;

    return true;
}

bool CMasternodeMan::PoSeBan(const COutPoint &outpoint)
{
    LOCK(cs);
    CMasternode* pmn = Find(outpoint);
    if (!pmn) {
        return false;
    }
    pmn->PoSeBan();

    return true;
}

void CMasternodeMan::Check()
{
    LOCK2(cs_main, cs);

//    LogPrint(BCLog::MN, "CMasternodeMan::Check -- nLastSentinelPingTime=%d, IsSentinelPingActive()=%d\n", nLastSentinelPingTime, IsSentinelPingActive());

    for (auto& mnpair : mapMasternodes) {
        // NOTE: internally it checks only every MASTERNODE_CHECK_SECONDS seconds
        // since the last time, so expect some MNs to skip this
        mnpair.second.Check();
    }
}

void CMasternodeMan::CheckAndRemove(CConnman& connman)
{
    if(!masternodeSync.IsMasternodeListSynced()) return;

    LogPrint(BCLog::MN, "CMasternodeMan::CheckAndRemove\n");

    {
        // Need LOCK2 here to ensure consistent locking order because code below locks cs_main
        // in CheckMnbAndUpdateMasternodeList()
        LOCK2(cs_main, cs);

        Check();

        // Remove spent masternodes, prepare structures and make requests to reasure the state of inactive ones
        rank_pair_vec_t vecMasternodeRanks;
        // ask for up to MNB_RECOVERY_MAX_ASK_ENTRIES masternode entries at a time
        int nAskForMnbRecovery = MNB_RECOVERY_MAX_ASK_ENTRIES;
        std::map<COutPoint, CMasternode>::iterator it = mapMasternodes.begin();
        while (it != mapMasternodes.end()) {
            CMasternodeBroadcast mnb = CMasternodeBroadcast(it->second);
            uint256 hash = mnb.GetHash();
            // If collateral was spent ...
            if (it->second.IsOutpointSpent() || (GetAdjustedTime() - it->second.lastPing.sigTime > 7 * 24 * 60 * 60)) {
                LogPrint(BCLog::MN, "CMasternodeMan::CheckAndRemove -- Removing Masternode: %s  addr=%s  %i now\n", it->second.GetStateString(), it->second.addr.ToString(), size() - 1);

                // erase all of the broadcasts we've seen from this txin, ...
                mapSeenMasternodeBroadcast.erase(hash);
                mWeAskedForMasternodeListEntry.erase(it->first);

                // and finally remove it from the list
                mapMasternodes.erase(it++);
                fMasternodesRemoved = true;
            } else {
                bool fAsk = (nAskForMnbRecovery > 0) &&
                            masternodeSync.IsSynced() &&
                            it->second.IsNewStartRequired() &&
                            !IsMnbRecoveryRequested(hash) &&
                            !gArgs.IsArgSet("-connect");
                if(fAsk) {
                    // this mn is in a non-recoverable state and we haven't asked other nodes yet
                    std::set<CService> setRequested;
                    // calulate only once and only when it's needed
                    if(vecMasternodeRanks.empty()) {
                        int nRandomBlockHeight = GetRandInt(nCachedBlockHeight);
                        GetMasternodeRanks(vecMasternodeRanks, nRandomBlockHeight);
                    }
                    bool fAskedForMnbRecovery = false;
                    // ask first MNB_RECOVERY_QUORUM_TOTAL masternodes we can connect to and we haven't asked recently
                    for(int i = 0; setRequested.size() < MNB_RECOVERY_QUORUM_TOTAL && i < (int)vecMasternodeRanks.size(); i++) {
                        // avoid banning
                        if(mWeAskedForMasternodeListEntry.count(it->first) && mWeAskedForMasternodeListEntry[it->first].count(vecMasternodeRanks[i].second.addr)) continue;
                        // didn't ask recently, ok to ask now
                        CService addr = vecMasternodeRanks[i].second.addr;
                        setRequested.insert(addr);
                        listScheduledMnbRequestConnections.push_back(std::make_pair(addr, hash));
                        fAskedForMnbRecovery = true;
                    }
                    if(fAskedForMnbRecovery) {
                        LogPrint(BCLog::MN, "CMasternodeMan::CheckAndRemove -- Recovery initiated, masternode=%s\n", it->first.ToString());
                        nAskForMnbRecovery--;
                    }
                    // wait for mnb recovery replies for MNB_RECOVERY_WAIT_SECONDS seconds
                    mMnbRecoveryRequests[hash] = std::make_pair(GetTime() + MNB_RECOVERY_WAIT_SECONDS, setRequested);
                }
                ++it;
            }
        }

        // proces replies for MASTERNODE_NEW_START_REQUIRED masternodes
        LogPrint(BCLog::MN, "CMasternodeMan::CheckAndRemove -- mMnbRecoveryGoodReplies size=%d\n", (int)mMnbRecoveryGoodReplies.size());
        std::map<uint256, std::vector<CMasternodeBroadcast> >::iterator itMnbReplies = mMnbRecoveryGoodReplies.begin();
        while(itMnbReplies != mMnbRecoveryGoodReplies.end()){
            if(mMnbRecoveryRequests[itMnbReplies->first].first < GetTime()) {
                // all nodes we asked should have replied now
                if(itMnbReplies->second.size() >= MNB_RECOVERY_QUORUM_REQUIRED) {
                    // majority of nodes we asked agrees that this mn doesn't require new mnb, reprocess one of new mnbs
                    LogPrint(BCLog::MN, "CMasternodeMan::CheckAndRemove -- reprocessing mnb, masternode=%s\n", itMnbReplies->second[0].outpoint.ToString());
                    // mapSeenMasternodeBroadcast.erase(itMnbReplies->first);
                    int nDos;
                    itMnbReplies->second[0].fRecovery = true;
                    CheckMnbAndUpdateMasternodeList(nullptr, itMnbReplies->second[0], nDos, connman);
                }
                LogPrint(BCLog::MN, "CMasternodeMan::CheckAndRemove -- removing mnb recovery reply, masternode=%s, size=%d\n", itMnbReplies->second[0].outpoint.ToString(), (int)itMnbReplies->second.size());
                mMnbRecoveryGoodReplies.erase(itMnbReplies++);
            } else {
                ++itMnbReplies;
            }
        }
    }
    {
        // no need for cm_main below
        LOCK(cs);

        auto itMnbRequest = mMnbRecoveryRequests.begin();
        while(itMnbRequest != mMnbRecoveryRequests.end()){
            // Allow this mnb to be re-verified again after MNB_RECOVERY_RETRY_SECONDS seconds
            // if mn is still in MASTERNODE_NEW_START_REQUIRED state.
            if(GetTime() - itMnbRequest->second.first > MNB_RECOVERY_RETRY_SECONDS) {
                mMnbRecoveryRequests.erase(itMnbRequest++);
            } else {
                ++itMnbRequest;
            }
        }

        // check who's asked for the Masternode list
        auto it1 = mAskedUsForMasternodeList.begin();
        while(it1 != mAskedUsForMasternodeList.end()){
            if((*it1).second < GetTime()) {
                mAskedUsForMasternodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check who we asked for the Masternode list
        it1 = mWeAskedForMasternodeList.begin();
        while(it1 != mWeAskedForMasternodeList.end()){
            if((*it1).second < GetTime()){
                mWeAskedForMasternodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check which Masternodes we've asked for
        auto it2 = mWeAskedForMasternodeListEntry.begin();
        while(it2 != mWeAskedForMasternodeListEntry.end()){
            auto it3 = it2->second.begin();
            while(it3 != it2->second.end()){
                if(it3->second < GetTime()){
                    it2->second.erase(it3++);
                } else {
                    ++it3;
                }
            }
            if(it2->second.empty()) {
                mWeAskedForMasternodeListEntry.erase(it2++);
            } else {
                ++it2;
            }
        }

        auto it3 = mWeAskedForVerification.begin();
        while(it3 != mWeAskedForVerification.end()){
            if(it3->second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
                mWeAskedForVerification.erase(it3++);
            } else {
                ++it3;
            }
        }

        // NOTE: do not expire mapSeenMasternodeBroadcast entries here, clean them on mnb updates!

        // remove expired mapSeenMasternodePing
        std::map<uint256, CMasternodePing>::iterator it4 = mapSeenMasternodePing.begin();
        while(it4 != mapSeenMasternodePing.end()){
            if((*it4).second.IsExpired()) {
                LogPrint(BCLog::MN, "CMasternodeMan::CheckAndRemove -- Removing expired Masternode ping: hash=%s\n", (*it4).second.GetHash().ToString());
                mapSeenMasternodePing.erase(it4++);
            } else {
                ++it4;
            }
        }

        // remove expired mapSeenMasternodeVerification
        std::map<uint256, CMasternodeVerification>::iterator itv2 = mapSeenMasternodeVerification.begin();
        while(itv2 != mapSeenMasternodeVerification.end()){
            if((*itv2).second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS){
                LogPrint(BCLog::MN, "CMasternodeMan::CheckAndRemove -- Removing expired Masternode verification: hash=%s\n", (*itv2).first.ToString());
                mapSeenMasternodeVerification.erase(itv2++);
            } else {
                ++itv2;
            }
        }

        LogPrint(BCLog::MN, "CMasternodeMan::CheckAndRemove -- %s\n", ToString());
    }

    if(fMasternodesRemoved) {
        NotifyMasternodeUpdates(connman);
    }
}

void CMasternodeMan::Clear()
{
    LOCK(cs);
    mapMasternodes.clear();
    mAskedUsForMasternodeList.clear();
    mWeAskedForMasternodeList.clear();
    mWeAskedForMasternodeListEntry.clear();
    mapSeenMasternodeBroadcast.clear();
    mapSeenMasternodePing.clear();
    nDsqCount = 0;
    nLastSentinelPingTime = 0;
}

int CMasternodeMan::CountMasternodes(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;

    for (const auto& mnpair : mapMasternodes) {
        nCount++;
    }

    return nCount;
}

int CMasternodeMan::CountEnabled(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;

    for (const auto& mnpair : mapMasternodes) {
        if (!mnpair.second.IsEnabled()) continue;
        nCount++;
    }

    return nCount;
}

/* Only IPv4 masternodes are allowed in 12.1, saving this for later
int CMasternodeMan::CountByIP(int nNetworkType)
{
    LOCK(cs);
    int nNodeCount = 0;

    for (const auto& mnpair : mapMasternodes)
        if ((nNetworkType == NET_IPV4 && mnpair.second.addr.IsIPv4()) ||
            (nNetworkType == NET_TOR  && mnpair.second.addr.IsTor())  ||
            (nNetworkType == NET_IPV6 && mnpair.second.addr.IsIPv6())) {
                nNodeCount++;
        }

    return nNodeCount;
}
*/

void CMasternodeMan::DsegUpdate(CNode* pnode, CConnman& connman)
{
    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    LOCK(cs);

    CService addrSquashed = (CService)pnode->addr;
        if(!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            auto it = mWeAskedForMasternodeList.find(addrSquashed);
            if(it != mWeAskedForMasternodeList.end() && GetTime() < (*it).second) {
                LogPrintf("CMasternodeMan::DsegUpdate -- we already asked %s for the list; skipping...\n", addrSquashed.ToString());
                return;
            }
        }

    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::DSEG, COutPoint()));
    int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
    mWeAskedForMasternodeList[addrSquashed] = askAgain;

    LogPrint(BCLog::MN, "CMasternodeMan::DsegUpdate -- asked %s for the list\n", pnode->addr.ToString());
}

CMasternode* CMasternodeMan::Find(const COutPoint &outpoint)
{
    LOCK(cs);
    auto it = mapMasternodes.find(outpoint);
    return it == mapMasternodes.end() ? nullptr : &(it->second);
}

bool CMasternodeMan::Get(const COutPoint& outpoint, CMasternode& masternodeRet)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    auto it = mapMasternodes.find(outpoint);
    if (it == mapMasternodes.end()) {
        return false;
    }

    masternodeRet = it->second;
    return true;
}

bool CMasternodeMan::GetMasternodeInfo(const COutPoint& outpoint, CMasternodeBase& mnInfoRet)
{
    LOCK(cs);
    auto it = mapMasternodes.find(outpoint);
    if (it == mapMasternodes.end()) {
        return false;
    }
    mnInfoRet = it->second.GetInfo();
    return true;
}

bool CMasternodeMan::GetMasternodeInfo(const CPubKey& pubKeyMasternode, CMasternodeBase& mnInfoRet)
{
    LOCK(cs);
    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.pubKeyMasternode == pubKeyMasternode) {
            mnInfoRet = mnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CMasternodeMan::GetMasternodeInfo(const CScript& payee, CMasternodeBase& mnInfoRet)
{
    LOCK(cs);
    for (const auto& mnpair : mapMasternodes) {
        CScript scriptCollateralAddress = GetScriptForDestination(mnpair.second.pubKeyCollateralAddress.GetID());
        if (scriptCollateralAddress == payee) {
            mnInfoRet = mnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CMasternodeMan::Has(const COutPoint& outpoint)
{
    LOCK(cs);
    return mapMasternodes.find(outpoint) != mapMasternodes.end();
}

//
// Deterministically select the oldest/best masternode to pay on the network
//
bool CMasternodeMan::GetNextMasternodeInQueueForPayment(bool fFilterSigTime, int& nCountRet, CMasternodeBase& mnInfoRet)
{
    return GetNextMasternodeInQueueForPayment(nCachedBlockHeight, fFilterSigTime, nCountRet, mnInfoRet);
}

bool CMasternodeMan::GetNextMasternodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCountRet, CMasternodeBase& mnInfoRet)
{
    mnInfoRet = CMasternodeBase();
    nCountRet = 0;

    if (!masternodeSync.IsWinnersListSynced()) {
        // without winner list we can't reliably find the next winner anyway
        return false;
    }

    // Need LOCK2 here to ensure consistent locking order because the GetBlockHash call below locks cs_main
    LOCK2(cs_main,cs);

    std::vector<std::pair<int, const CMasternode*> > vecMasternodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */

    int nMnCount = CountMasternodes();

    for (const auto& mnpair : mapMasternodes) {
        if(!mnpair.second.IsValidForPayment()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if(mnpayments.IsScheduled(mnpair.second, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if(fFilterSigTime && mnpair.second.sigTime + (nMnCount*2.6*60) > GetAdjustedTime()) continue;

        //make sure it has at least as many confirmations as there are masternodes
        if(GetUTXOConfirmations(mnpair.first) < nMnCount) continue;

        vecMasternodeLastPaid.push_back(std::make_pair(mnpair.second.GetLastPaidBlock(), &mnpair.second));
    }

    nCountRet = (int)vecMasternodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if(fFilterSigTime && nCountRet < nMnCount/3)
        return GetNextMasternodeInQueueForPayment(nBlockHeight, false, nCountRet, mnInfoRet);

    // Sort them low to high
    sort(vecMasternodeLastPaid.begin(), vecMasternodeLastPaid.end(), CompareLastPaidBlock());

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight - 101)) {
        LogPrintf("CMasternode::GetNextMasternodeInQueueForPayment -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", nBlockHeight - 101);
        return false;
    }
    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = nMnCount/10;
    int nCountTenth = 0;
    arith_uint256 nHighest = 0;
    const CMasternode *pBestMasternode = nullptr;
    for (const auto& s : vecMasternodeLastPaid) {
        arith_uint256 nScore = s.second->CalculateScore(blockHash);
        if(nScore > nHighest){
            nHighest = nScore;
            pBestMasternode = s.second;
        }
        nCountTenth++;
        if(nCountTenth >= nTenthNetwork) break;
    }
    if (pBestMasternode) {
        mnInfoRet = pBestMasternode->GetInfo();
    }
    return mnInfoRet.fInfoValid;
}

CMasternodeBase CMasternodeMan::FindRandomNotInVec(const std::vector<COutPoint> &vecToExclude, int nProtocolVersion)
{
    LOCK(cs);

    int nCountEnabled = CountEnabled(nProtocolVersion);
    int nCountNotExcluded = nCountEnabled - vecToExclude.size();

    LogPrintf("CMasternodeMan::FindRandomNotInVec -- %d enabled masternodes, %d masternodes to choose from\n", nCountEnabled, nCountNotExcluded);
    if(nCountNotExcluded < 1) return CMasternodeBase();

    // fill a vector of pointers
    std::vector<const CMasternode*> vpMasternodesShuffled;
    for (const auto& mnpair : mapMasternodes) {
        vpMasternodesShuffled.push_back(&mnpair.second);
    }

    FastRandomContext insecure_rand;
    // shuffle pointers
    std::random_shuffle(vpMasternodesShuffled.begin(), vpMasternodesShuffled.end(), insecure_rand);
    bool fExclude;

    // loop through
    for (const auto& pmn : vpMasternodesShuffled) {
        if(pmn->nProtocolVersion < nProtocolVersion || !pmn->IsEnabled()) continue;
        fExclude = false;
        for (const auto& outpointToExclude : vecToExclude) {
            if(pmn->outpoint == outpointToExclude) {
                fExclude = true;
                break;
            }
        }
        if(fExclude) continue;
        // found the one not in vecToExclude
        LogPrint(BCLog::MN, "CMasternodeMan::FindRandomNotInVec -- found, masternode=%s\n", pmn->outpoint.ToString());
        return pmn->GetInfo();
    }

    LogPrint(BCLog::MN, "CMasternodeMan::FindRandomNotInVec -- failed\n");
    return CMasternodeBase();
}

bool CMasternodeMan::GetMasternodeScores(const uint256& nBlockHash, CMasternodeMan::score_pair_vec_t& vecMasternodeScoresRet, int nMinProtocol)
{
    vecMasternodeScoresRet.clear();

    if (!masternodeSync.IsMasternodeListSynced())
        return false;

    AssertLockHeld(cs);

    if (mapMasternodes.empty())
        return false;

    // calculate scores
    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.nProtocolVersion >= nMinProtocol) {
            vecMasternodeScoresRet.push_back(std::make_pair(mnpair.second.CalculateScore(nBlockHash), &mnpair.second));
        }
    }

    sort(vecMasternodeScoresRet.rbegin(), vecMasternodeScoresRet.rend(), CompareScoreMN());
    return !vecMasternodeScoresRet.empty();
}

bool CMasternodeMan::GetMasternodeRank(const COutPoint& outpoint, int& nRankRet, int nBlockHeight, int nMinProtocol)
{
    nRankRet = -1;

    if (!masternodeSync.IsMasternodeListSynced())
        return false;

    // make sure we know about this block
    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, nBlockHeight)) {
        LogPrintf("CMasternodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    LOCK(cs);

    score_pair_vec_t vecMasternodeScores;
    if (!GetMasternodeScores(nBlockHash, vecMasternodeScores, nMinProtocol))
        return false;

    int nRank = 0;
    for (const auto& scorePair : vecMasternodeScores) {
        nRank++;
        if(scorePair.second->outpoint == outpoint) {
            nRankRet = nRank;
            return true;
        }
    }

    return false;
}

bool CMasternodeMan::GetMasternodeRanks(CMasternodeMan::rank_pair_vec_t& vecMasternodeRanksRet, int nBlockHeight, int nMinProtocol)
{
    vecMasternodeRanksRet.clear();

    if (!masternodeSync.IsMasternodeListSynced())
        return false;

    // make sure we know about this block
    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, nBlockHeight)) {
        LogPrintf("CMasternodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    LOCK(cs);

    score_pair_vec_t vecMasternodeScores;
    if (!GetMasternodeScores(nBlockHash, vecMasternodeScores, nMinProtocol))
        return false;

    int nRank = 0;
    for (const auto& scorePair : vecMasternodeScores) {
        nRank++;
        vecMasternodeRanksRet.push_back(std::make_pair(nRank, *scorePair.second));
    }

    return true;
}

void CMasternodeMan::ProcessMasternodeConnections(CConnman& connman)
{
    connman.ForEachNode([](CNode* pnode) {
        if (pnode->fMasternode) {
            LogPrintf("Closing Masternode connection: peer=%d, addr=%s\n", pnode->GetId(), pnode->addr.ToString());
            pnode->fDisconnect = true;
        }
    });
}

std::pair<CService, std::set<uint256> > CMasternodeMan::PopScheduledMnbRequestConnection()
{
    LOCK(cs);
    if(listScheduledMnbRequestConnections.empty()) {
        return std::make_pair(CService(), std::set<uint256>());
    }

    std::set<uint256> setResult;

    listScheduledMnbRequestConnections.sort();
    std::pair<CService, uint256> pairFront = listScheduledMnbRequestConnections.front();

    // squash hashes from requests with the same CService as the first one into setResult
    std::list< std::pair<CService, uint256> >::iterator it = listScheduledMnbRequestConnections.begin();
    while(it != listScheduledMnbRequestConnections.end()) {
        if(pairFront.first == it->first) {
            setResult.insert(it->second);
            it = listScheduledMnbRequestConnections.erase(it);
        } else {
            // since list is sorted now, we can be sure that there is no more hashes left
            // to ask for from this addr
            break;
        }
    }
    return std::make_pair(pairFront.first, setResult);
}

void CMasternodeMan::ProcessPendingMnbRequests(CConnman& connman)
{
    std::pair<CService, std::set<uint256> > p = PopScheduledMnbRequestConnection();
    if (!(p.first == CService() || p.second.empty())) {
        bool ret = false;
        CService& addr = p.first;
        connman.ForEachNode([&ret, &addr](CNode* pnode) {
            if ((CService)pnode->addr == addr) {
                if (pnode->fMasternode || pnode->fDisconnect) ret = true;
            }
        });
        if (ret) return;
        mapPendingMNB.insert(std::make_pair(p.first, std::make_pair(GetTime(), p.second)));
        connman.AddPendingMasternode(p.first);
    }

    std::map<CService, std::pair<int64_t, std::set<uint256> > >::iterator itPendingMNB = mapPendingMNB.begin();
    while (itPendingMNB != mapPendingMNB.end()) {
        bool fDone = false;
        connman.ForEachNode([&connman, &fDone, &itPendingMNB](CNode* pnode) {
            if ((CService)pnode->addr == itPendingMNB->first) {
                std::vector<CInv> vToFetch;
                std::set<uint256>& setHashes = itPendingMNB->second.second;
                std::set<uint256>::iterator it = setHashes.begin();
                while(it != setHashes.end()) {
                    if(*it != uint256()) {
                        vToFetch.push_back(CInv(MSG_MASTERNODE_ANNOUNCE, *it));
                        LogPrint(BCLog::MN, "-- asking for mnb %s from addr=%s\n", it->ToString(), pnode->addr.ToString());
                    }
                    ++it;
                }
                // ask for data
                CNetMsgMaker msgMaker(pnode->GetSendVersion());
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
                fDone = true;
            }
        });
        
        int64_t nTimeAdded = itPendingMNB->second.first;
        if (fDone || (GetTime() - nTimeAdded > 15)) {
            if (!fDone) {
                LogPrint(BCLog::MN, "CMasternodeMan::%s -- failed to connect to %s\n", __func__, itPendingMNB->first.ToString());
            }
            mapPendingMNB.erase(itPendingMNB++);
        } else {
            ++itPendingMNB;
        }
    }
//    LogPrint(BCLog::MN, "%s -- mapPendingMNB size: %d\n", __func__, mapPendingMNB.size());
}

bool CMasternodeMan::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if (strCommand == NetMsgType::MNANNOUNCE) { //Masternode Broadcast

        CMasternodeBroadcast mnb;
        vRecv >> mnb;

        pfrom->setAskFor.erase(mnb.GetHash());

        if(!masternodeSync.IsBlockchainSynced()) return true;

        LogPrint(BCLog::MN, "MNANNOUNCE -- Masternode announce, masternode=%s\n", mnb.outpoint.ToString());

        int nDos = 0;

        if (CheckMnbAndUpdateMasternodeList(pfrom, mnb, nDos, connman)) {
            // use announced Masternode as a peer
            std::vector<CAddress> vAddr;
            vAddr.push_back (CAddress(mnb.addr, NODE_NETWORK));
            connman.AddNewAddresses(vAddr, pfrom->addr, 2 * 60 * 60);
        } else if(nDos > 0) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), nDos, "");
        }

        if(fMasternodesAdded) {
            NotifyMasternodeUpdates(connman);
        }
        return true;
    } else if (strCommand == NetMsgType::MNPING) { //Masternode Ping

        CMasternodePing mnp;
        vRecv >> mnp;

        uint256 nHash = mnp.GetHash();

        pfrom->setAskFor.erase(nHash);

        if(!masternodeSync.IsBlockchainSynced()) return true;

        LogPrint(BCLog::MN, "MNPING -- Masternode ping, masternode=%s\n", mnp.masternodeOutpoint.ToString());

        // Need LOCK2 here to ensure consistent locking order because the CheckAndUpdate call below locks cs_main
        LOCK2(cs_main, cs);

        if(mapSeenMasternodePing.count(nHash)) return true; //seen
        mapSeenMasternodePing.insert(std::make_pair(nHash, mnp));

        LogPrint(BCLog::MN, "MNPING -- Masternode ping, masternode=%s new\n", mnp.masternodeOutpoint.ToString());

        // see if we have this Masternode
        CMasternode* pmn = Find(mnp.masternodeOutpoint);

        if(pmn && mnp.fSentinelIsCurrent)
            UpdateLastSentinelPingTime();

        // too late, new MNANNOUNCE is required
        if(pmn && pmn->IsNewStartRequired()) return true;

        int nDos = 0;
        if(mnp.CheckAndUpdate(pmn, false, nDos, connman)) return true;

        if(nDos > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDos, "");
        } else if (pmn != nullptr) {
            // nothing significant failed, mn is a known one too
            return true;
        }

        // something significant is broken or mn is unknown,
        // we might have to ask for a masternode entry once
        AskForMN(pfrom, mnp.masternodeOutpoint, connman);
        return true;
    } else if (strCommand == NetMsgType::DSEG) { //Get Masternode list or specific entry
        // Ignore such requests until we are fully synced.
        // We could start processing this after masternode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!masternodeSync.IsSynced()) return true;

        COutPoint masternodeOutpoint;

        vRecv >> masternodeOutpoint;

        LogPrint(BCLog::MN, "DSEG -- Masternode list, masternode=%s\n", masternodeOutpoint.ToString());

        if(masternodeOutpoint.IsNull()) {
            SyncAll(pfrom, connman);
        } else {
            SyncSingle(pfrom, masternodeOutpoint, connman);
        }
        return true;
    } else if (strCommand == NetMsgType::MNVERIFY) { // Masternode Verify

        // Need LOCK2 here to ensure consistent locking order because all functions below call GetBlockHash which locks cs_main
        LOCK2(cs_main, cs);

        CMasternodeVerification mnv;
        vRecv >> mnv;

        pfrom->setAskFor.erase(mnv.GetHash());

        if(!masternodeSync.IsMasternodeListSynced()) return true;

        if(mnv.vchSig1.empty()) {
            // CASE 1: someone asked me to verify myself /IP we are using/
            SendVerifyReply(pfrom, mnv, connman);
        } else if (mnv.vchSig2.empty()) {
            // CASE 2: we _probably_ got verification we requested from some masternode
            ProcessVerifyReply(pfrom, mnv);
        } else {
            // CASE 3: we _probably_ got verification broadcast signed by some masternode which verified another one
            ProcessVerifyBroadcast(pfrom, mnv);
        }
        return true;
    }
    return false;
}

void CMasternodeMan::SyncSingle(CNode* pnode, const COutPoint& outpoint, CConnman& connman)
{
    // do not provide any data until our node is synced
    if (!masternodeSync.IsSynced()) return;

    LOCK(cs);

    auto it = mapMasternodes.find(outpoint);

    if(it != mapMasternodes.end()) {
        if (it->second.addr.IsRFC1918() || it->second.addr.IsLocal()) return; // do not send local network masternode
        // NOTE: send masternode regardless of its current state, the other node will need it to verify old votes.
        LogPrint(BCLog::MN, "CMasternodeMan::%s -- Sending Masternode entry: masternode=%s  addr=%s\n", __func__, outpoint.ToString(), it->second.addr.ToString());
        PushDsegInvs(pnode, it->second);
        LogPrintf("CMasternodeMan::%s -- Sent 1 Masternode inv to peer=%d\n", __func__, pnode->GetId());
    }
}

void CMasternodeMan::SyncAll(CNode* pnode, CConnman& connman)
{
    // do not provide any data until our node is synced
    if (!masternodeSync.IsSynced()) return;

    // local network
    bool isLocal = (pnode->addr.IsRFC1918() || pnode->addr.IsLocal());

    CService addrSquashed = (CService)pnode->addr;
    // should only ask for this once
    if(!isLocal && Params().NetworkIDString() == CBaseChainParams::MAIN) {
        LOCK2(cs_main, cs);
        auto it = mAskedUsForMasternodeList.find(addrSquashed);
        if (it != mAskedUsForMasternodeList.end() && it->second > GetTime()) {
            Misbehaving(pnode->GetId(), 34, "");
            LogPrintf("CMasternodeMan::%s -- peer already asked me for the list, peer=%d\n", __func__, pnode->GetId());
            return;
        }
        int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
        mAskedUsForMasternodeList[addrSquashed] = askAgain;
    }

    int nInvCount = 0;

    LOCK(cs);

    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.addr.IsRFC1918() || mnpair.second.addr.IsLocal()) continue; // do not send local network masternode
        // NOTE: send masternode regardless of its current state, the other node will need it to verify old votes.
        LogPrint(BCLog::MN, "CMasternodeMan::%s -- Sending Masternode entry: masternode=%s  addr=%s\n", __func__, mnpair.first.ToString(), mnpair.second.addr.ToString());
        PushDsegInvs(pnode, mnpair.second);
        nInvCount++;
    }

    connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_LIST, nInvCount));
    LogPrintf("CMasternodeMan::%s -- Sent %d Masternode invs to peer=%d\n", __func__, nInvCount, pnode->GetId());
}

void CMasternodeMan::PushDsegInvs(CNode* pnode, const CMasternode& mn)
{
    AssertLockHeld(cs);

    CMasternodeBroadcast mnb(mn);
    CMasternodePing mnp = mnb.lastPing;
    uint256 hashMNB = mnb.GetHash();
    uint256 hashMNP = mnp.GetHash();
    pnode->PushInventory(CInv(MSG_MASTERNODE_ANNOUNCE, hashMNB));
    pnode->PushInventory(CInv(MSG_MASTERNODE_PING, hashMNP));
    mapSeenMasternodeBroadcast.insert(std::make_pair(hashMNB, std::make_pair(GetTime(), mnb)));
    mapSeenMasternodePing.insert(std::make_pair(hashMNP, mnp));
}

// Verification of masternodes via unique direct requests.

void CMasternodeMan::DoFullVerificationStep(CConnman& connman)
{
    if(activeMasternode.outpoint.IsNull()) return;
    if(!masternodeSync.IsSynced()) return;

    rank_pair_vec_t vecMasternodeRanks;
    GetMasternodeRanks(vecMasternodeRanks, nCachedBlockHeight - 1, 0);

    LOCK(cs);

    int nCount = 0;

    int nMyRank = -1;
    int nRanksTotal = (int)vecMasternodeRanks.size();

    // send verify requests only if we are in top MAX_POSE_RANK
    rank_pair_vec_t::iterator it = vecMasternodeRanks.begin();
    while(it != vecMasternodeRanks.end()) {
        if(it->first > MAX_POSE_RANK) {
            LogPrint(BCLog::MN, "CMasternodeMan::DoFullVerificationStep -- Must be in top %d to send verify request\n",
                        (int)MAX_POSE_RANK);
            return;
        }
        if(it->second.outpoint == activeMasternode.outpoint) {
            nMyRank = it->first;
            LogPrint(BCLog::MN, "CMasternodeMan::DoFullVerificationStep -- Found self at rank %d/%d, verifying up to %d masternodes\n",
                        nMyRank, nRanksTotal, (int)MAX_POSE_CONNECTIONS);
            break;
        }
        ++it;
    }

    // edge case: list is too short and this masternode is not enabled
    if(nMyRank == -1) return;

    // send verify requests to up to MAX_POSE_CONNECTIONS masternodes
    // starting from MAX_POSE_RANK + nMyRank and using MAX_POSE_CONNECTIONS as a step
    int nOffset = MAX_POSE_RANK + nMyRank - 1;
    if(nOffset >= (int)vecMasternodeRanks.size()) return;

    std::vector<const CMasternode*> vSortedByAddr;
    for (const auto& mnpair : mapMasternodes) {
        vSortedByAddr.push_back(&mnpair.second);
    }

    sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

    it = vecMasternodeRanks.begin() + nOffset;
    while(it != vecMasternodeRanks.end()) {
        if(it->second.IsPoSeVerified() || it->second.IsPoSeBanned()) {
            LogPrint(BCLog::MN, "CMasternodeMan::DoFullVerificationStep -- Already %s%s%s masternode %s address %s, skipping...\n",
                        it->second.IsPoSeVerified() ? "verified" : "",
                        it->second.IsPoSeVerified() && it->second.IsPoSeBanned() ? " and " : "",
                        it->second.IsPoSeBanned() ? "banned" : "",
                        it->second.outpoint.ToString(), it->second.addr.ToString());
            nOffset += MAX_POSE_CONNECTIONS;
            if(nOffset >= (int)vecMasternodeRanks.size()) break;
            it += MAX_POSE_CONNECTIONS;
            continue;
        }
        LogPrint(BCLog::MN, "CMasternodeMan::DoFullVerificationStep -- Verifying masternode %s rank %d/%d address %s\n",
                    it->second.outpoint.ToString(), it->first, nRanksTotal, it->second.addr.ToString());
        if(SendVerifyRequest(CAddress(it->second.addr, NODE_NETWORK), vSortedByAddr, connman)) {
            nCount++;
            if(nCount >= MAX_POSE_CONNECTIONS) break;
        }
        nOffset += MAX_POSE_CONNECTIONS;
        if(nOffset >= (int)vecMasternodeRanks.size()) break;
        it += MAX_POSE_CONNECTIONS;
    }

    LogPrint(BCLog::MN, "CMasternodeMan::DoFullVerificationStep -- Sent verification requests to %d masternodes\n", nCount);
}

// This function tries to find masternodes with the same addr,
// find a verified one and ban all the other. If there are many nodes
// with the same addr but none of them is verified yet, then none of them are banned.
// It could take many times to run this before most of the duplicate nodes are banned.

void CMasternodeMan::CheckSameAddr()
{
    if(!masternodeSync.IsSynced() || mapMasternodes.empty()) return;

    std::vector<CMasternode*> vBan;
    std::vector<CMasternode*> vSortedByAddr;

    {
        LOCK(cs);

        CMasternode* pprevMasternode = nullptr;
        CMasternode* pverifiedMasternode = nullptr;

        for (auto& mnpair : mapMasternodes) {
            vSortedByAddr.push_back(&mnpair.second);
        }

        sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

        for (const auto& pmn : vSortedByAddr) {
            // check only (pre)enabled masternodes
            if(!pmn->IsEnabled() && !pmn->IsPreEnabled()) continue;
            // initial step
            if(!pprevMasternode) {
                pprevMasternode = pmn;
                pverifiedMasternode = pmn->IsPoSeVerified() ? pmn : nullptr;
                continue;
            }
            // second+ step
            if(pmn->addr == pprevMasternode->addr) {
                if(pverifiedMasternode) {
                    // another masternode with the same ip is verified, ban this one
                    vBan.push_back(pmn);
                } else if(pmn->IsPoSeVerified()) {
                    // this masternode with the same ip is verified, ban previous one
                    vBan.push_back(pprevMasternode);
                    // and keep a reference to be able to ban following masternodes with the same ip
                    pverifiedMasternode = pmn;
                }
            } else {
                pverifiedMasternode = pmn->IsPoSeVerified() ? pmn : nullptr;
            }
            pprevMasternode = pmn;
        }
    }

    // ban duplicates
    for (auto& pmn : vBan) {
        LogPrintf("CMasternodeMan::CheckSameAddr -- increasing PoSe ban score for masternode %s\n", pmn->outpoint.ToString());
        pmn->IncreasePoSeBanScore();
    }
}

bool CMasternodeMan::SendVerifyRequest(const CAddress& addr, const std::vector<const CMasternode*>& vSortedByAddr, CConnman& connman)
{
    if (netfulfilledman.HasFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        // we already asked for verification, not a good idea to do this too often, skip it
        LogPrint(BCLog::MN, "CMasternodeMan::SendVerifyRequest -- too many requests, skipping... addr=%s\n", addr.ToString());
        return false;
    }

    bool ret = false;
    connman.ForEachNode([&ret, &addr](CNode* pnode) {
        if ((CService)pnode->addr == addr) {
            if (pnode->fMasternode || pnode->fDisconnect) ret = true;
        }
    });
    if (ret) return false;

    connman.AddPendingMasternode(addr);
    // use random nonce, store it and require node to reply with correct one later
    CMasternodeVerification mnv(addr, GetRandInt(999999), nCachedBlockHeight - 1);
    LOCK(cs_mapPendingMNV);
    mapPendingMNV.insert(std::make_pair(addr, std::make_pair(GetTime(), mnv)));
    LogPrintf("CMasternodeMan::SendVerifyRequest -- verifying node using nonce %d addr=%s\n", mnv.nonce, addr.ToString());
    return true;
}

void CMasternodeMan::ProcessPendingMnvRequests(CConnman& connman)
{
    LOCK(cs_mapPendingMNV);

    std::map<CService, std::pair<int64_t, CMasternodeVerification> >::iterator itPendingMNV = mapPendingMNV.begin();

    while (itPendingMNV != mapPendingMNV.end()) {
        bool fDone = false;
        connman.ForEachNode([&connman, &fDone, &itPendingMNV, this](CNode* pnode) {
            if ((CService)pnode->addr == itPendingMNV->first) {
                netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request");
                // use random nonce, store it and require node to reply with correct one later
                mWeAskedForVerification[pnode->addr] = itPendingMNV->second.second;
                LogPrint(BCLog::MN, "-- verifying node using nonce %d addr=%s\n", itPendingMNV->second.second.nonce, pnode->addr.ToString());
                CNetMsgMaker msgMaker(pnode->GetSendVersion()); // TODO this gives a warning about version not being set (we should wait for VERSION exchange)
                connman.PushMessage(pnode, msgMaker.Make(NetMsgType::MNVERIFY, itPendingMNV->second.second));
                fDone = true;
            }
        });

        int64_t nTimeAdded = itPendingMNV->second.first;
        if (fDone || (GetTime() - nTimeAdded > 15)) {
            if (!fDone) {
                LogPrint(BCLog::MN, "CMasternodeMan::%s -- failed to connect to %s\n", __func__, itPendingMNV->first.ToString());
            }
            mapPendingMNV.erase(itPendingMNV++);
        } else {
            ++itPendingMNV;
        }
    }
//    LogPrint(BCLog::MN, "%s -- mapPendingMNV size: %d\n", __func__, mapPendingMNV.size());
}

void CMasternodeMan::SendVerifyReply(CNode* pnode, CMasternodeVerification& mnv, CConnman& connman)
{
    AssertLockHeld(cs_main);

    // only masternodes can sign this, why would someone ask regular node?
    if(!fMasternodeMode) {
        // do not ban, malicious node might be using my IP
        // and trying to confuse the node which tries to verify it
        return;
    }

    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply")) {
        // peer should not ask us that often
        LogPrintf("MasternodeMan::SendVerifyReply -- ERROR: peer already asked me recently, peer=%d\n", pnode->GetId());
        Misbehaving(pnode->GetId(), 20, "");
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        LogPrintf("MasternodeMan::SendVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    std::string strError;

    {
        std::string strMessage = strprintf("%s%d%s", activeMasternode.service.ToString(), mnv.nonce, blockHash.ToString());

        if(!CMessageSigner::SignMessage(strMessage, mnv.vchSig1, activeMasternode.keyMasternode)) {
            LogPrintf("MasternodeMan::SendVerifyReply -- SignMessage() failed\n");
            return;
        }

        if(!CMessageSigner::VerifyMessage(activeMasternode.pubKeyMasternode, mnv.vchSig1, strMessage, strError)) {
            LogPrintf("MasternodeMan::SendVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
            return;
        }
    }

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    connman.PushMessage(pnode, msgMaker.Make(NetMsgType::MNVERIFY, mnv));
    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply");
}

void CMasternodeMan::ProcessVerifyReply(CNode* pnode, CMasternodeVerification& mnv)
{
    AssertLockHeld(cs_main);

    std::string strError;

    // did we even ask for it? if that's the case we should have matching fulfilled request
    if(!netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: we didn't ask for verification of %s, peer=%d\n", pnode->addr.ToString(), pnode->GetId());
        Misbehaving(pnode->GetId(), 20, "");
        return;
    }

    // Received nonce for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nonce != mnv.nonce) {
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: wrong nounce: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nonce, mnv.nonce, pnode->GetId());
        Misbehaving(pnode->GetId(), 20, "");
        return;
    }

    // Received nBlockHeight for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nBlockHeight != mnv.nBlockHeight) {
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: wrong nBlockHeight: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nBlockHeight, mnv.nBlockHeight, pnode->GetId());
        Misbehaving(pnode->GetId(), 20, "");
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("MasternodeMan::ProcessVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    // we already verified this address, why node is spamming?
    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done")) {
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: already verified %s recently\n", pnode->addr.ToString());
        Misbehaving(pnode->GetId(), 20, "");
        return;
    }

    {
        LOCK(cs);

        CMasternode* prealMasternode = nullptr;
        std::vector<CMasternode*> vpMasternodesToBan;

        uint256 hash1 = mnv.GetSignatureHash1(blockHash);
        std::string strMessage1 = strprintf("%s%d%s", pnode->addr.ToString(), mnv.nonce, blockHash.ToString());

        for (auto& mnpair : mapMasternodes) {
            if(CAddress(mnpair.second.addr, NODE_NETWORK) == pnode->addr) {
                bool fFound = false;
                {
                    fFound = CMessageSigner::VerifyMessage(mnpair.second.pubKeyMasternode, mnv.vchSig1, strMessage1, strError);
                }
                if (fFound) {
                    // found it!
                    prealMasternode = &mnpair.second;
                    if(!mnpair.second.IsPoSeVerified()) {
                        mnpair.second.DecreasePoSeBanScore();
                    }
                    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done");

                    // we can only broadcast it if we are an activated masternode
                    if(activeMasternode.outpoint.IsNull()) continue;
                    // update ...
                    mnv.addr = mnpair.second.addr;
                    mnv.masternodeOutpoint1 = mnpair.second.outpoint;
                    mnv.masternodeOutpoint2 = activeMasternode.outpoint;
                    // ... and sign it
                    std::string strError;

                    {
                        std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString(),
                                                mnv.masternodeOutpoint1.ToString(), mnv.masternodeOutpoint2.ToString());

                        if(!CMessageSigner::SignMessage(strMessage2, mnv.vchSig2, activeMasternode.keyMasternode)) {
                            LogPrintf("MasternodeMan::ProcessVerifyReply -- SignMessage() failed\n");
                            return;
                        }

                        if(!CMessageSigner::VerifyMessage(activeMasternode.pubKeyMasternode, mnv.vchSig2, strMessage2, strError)) {
                            LogPrintf("MasternodeMan::ProcessVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
                            return;
                        }
                    }

                    mWeAskedForVerification[pnode->addr] = mnv;
                    mapSeenMasternodeVerification.insert(std::make_pair(mnv.GetHash(), mnv));
                    mnv.Relay();

                } else {
                    vpMasternodesToBan.push_back(&mnpair.second);
                }
            }
        }
        // no real masternode found?...
        if(!prealMasternode) {
            // this should never be the case normally,
            // only if someone is trying to game the system in some way or smth like that
            LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: no real masternode found for addr %s\n", pnode->addr.ToString());
            Misbehaving(pnode->GetId(), 20, "");
            return;
        }
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- verified real masternode %s for addr %s\n",
                    prealMasternode->outpoint.ToString(), pnode->addr.ToString());
        // increase ban score for everyone else
        for (const auto& pmn : vpMasternodesToBan) {
            pmn->IncreasePoSeBanScore();
            LogPrint(BCLog::MN, "CMasternodeMan::ProcessVerifyReply -- increased PoSe ban score for %s addr %s, new score %d\n",
                        prealMasternode->outpoint.ToString(), pnode->addr.ToString(), pmn->nPoSeBanScore);
        }
        if(!vpMasternodesToBan.empty())
            LogPrintf("CMasternodeMan::ProcessVerifyReply -- PoSe score increased for %d fake masternodes, addr %s\n",
                        (int)vpMasternodesToBan.size(), pnode->addr.ToString());
    }
}

void CMasternodeMan::ProcessVerifyBroadcast(CNode* pnode, const CMasternodeVerification& mnv)
{
    AssertLockHeld(cs_main);

    std::string strError;

    if(mapSeenMasternodeVerification.find(mnv.GetHash()) != mapSeenMasternodeVerification.end()) {
        // we already have one
        return;
    }
    mapSeenMasternodeVerification[mnv.GetHash()] = mnv;

    // we don't care about history
    if(mnv.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
        LogPrint(BCLog::MN, "CMasternodeMan::ProcessVerifyBroadcast -- Outdated: current block %d, verification block %d, peer=%d\n",
                    nCachedBlockHeight, mnv.nBlockHeight, pnode->GetId());
        return;
    }

    if(mnv.masternodeOutpoint1 == mnv.masternodeOutpoint2) {
        LogPrint(BCLog::MN, "CMasternodeMan::ProcessVerifyBroadcast -- ERROR: same outpoints %s, peer=%d\n",
                    mnv.masternodeOutpoint1.ToString(), pnode->GetId());
        // that was NOT a good idea to cheat and verify itself,
        // ban the node we received such message from
        Misbehaving(pnode->GetId(), 100, "");
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- Can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    int nRank;

    if (!GetMasternodeRank(mnv.masternodeOutpoint2, nRank, mnv.nBlockHeight, 0)) {
        LogPrint(BCLog::MN, "CMasternodeMan::ProcessVerifyBroadcast -- Can't calculate rank for masternode %s\n",
                    mnv.masternodeOutpoint2.ToString());
        return;
    }

    if(nRank > MAX_POSE_RANK) {
        LogPrint(BCLog::MN, "CMasternodeMan::ProcessVerifyBroadcast -- Masternode %s is not in top %d, current rank %d, peer=%d\n",
                    mnv.masternodeOutpoint2.ToString(), (int)MAX_POSE_RANK, nRank, pnode->GetId());
        return;
    }

    {
        LOCK(cs);

        CMasternode* pmn1 = Find(mnv.masternodeOutpoint1);
        if(!pmn1) {
            LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- can't find masternode1 %s\n", mnv.masternodeOutpoint1.ToString());
            return;
        }

        CMasternode* pmn2 = Find(mnv.masternodeOutpoint2);
        if(!pmn2) {
            LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- can't find masternode2 %s\n", mnv.masternodeOutpoint2.ToString());
            return;
        }

        if(pmn1->addr != mnv.addr) {
            LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- addr %s does not match %s\n", mnv.addr.ToString(), pmn1->addr.ToString());
            return;
        }

        {
            std::string strMessage1 = strprintf("%s%d%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString());
            std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString(),
                                    mnv.masternodeOutpoint1.ToString(), mnv.masternodeOutpoint2.ToString());

            if(!CMessageSigner::VerifyMessage(pmn1->pubKeyMasternode, mnv.vchSig1, strMessage1, strError)) {
                LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- VerifyMessage() for masternode1 failed, error: %s\n", strError);
                return;
            }

            if(!CMessageSigner::VerifyMessage(pmn2->pubKeyMasternode, mnv.vchSig2, strMessage2, strError)) {
                LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- VerifyMessage() for masternode2 failed, error: %s\n", strError);
                return;
            }
        }

        if(!pmn1->IsPoSeVerified()) {
            pmn1->DecreasePoSeBanScore();
        }
        mnv.Relay();

        LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- verified masternode %s for addr %s\n",
                    pmn1->outpoint.ToString(), pmn1->addr.ToString());

        // increase ban score for everyone else with the same addr
        int nCount = 0;
        for (auto& mnpair : mapMasternodes) {
            if(mnpair.second.addr != mnv.addr || mnpair.first == mnv.masternodeOutpoint1) continue;
            mnpair.second.IncreasePoSeBanScore();
            nCount++;
            LogPrint(BCLog::MN, "CMasternodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                        mnpair.first.ToString(), mnpair.second.addr.ToString(), mnpair.second.nPoSeBanScore);
        }
        if(nCount)
            LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- PoSe score increased for %d fake masternodes, addr %s\n",
                        nCount, pmn1->addr.ToString());
    }
}

std::string CMasternodeMan::ToString() const
{
    std::ostringstream info;

    info << "Masternodes: " << (int)mapMasternodes.size() <<
            ", peers who asked us for Masternode list: " << (int)mAskedUsForMasternodeList.size() <<
            ", peers we asked for Masternode list: " << (int)mWeAskedForMasternodeList.size() <<
            ", entries in Masternode list we asked for: " << (int)mWeAskedForMasternodeListEntry.size() <<
            ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}

bool CMasternodeMan::CheckMnbAndUpdateMasternodeList(CNode* pfrom, CMasternodeBroadcast mnb, int& nDos, CConnman& connman)
{
    // Need to lock cs_main here to ensure consistent locking order because the SimpleCheck call below locks cs_main
    LOCK(cs_main);

    {
        LOCK(cs);
        nDos = 0;
        LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s\n", mnb.outpoint.ToString());

        uint256 hash = mnb.GetHash();
        if(mapSeenMasternodeBroadcast.count(hash) && !mnb.fRecovery) { //seen
            LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s seen\n", mnb.outpoint.ToString());
            // less then 2 pings left before this MN goes into non-recoverable state, bump sync timeout
            if(GetTime() - mapSeenMasternodeBroadcast[hash].first > MASTERNODE_NEW_START_REQUIRED_SECONDS - MASTERNODE_MIN_MNP_SECONDS * 2) {
                LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s seen update\n", mnb.outpoint.ToString());
                mapSeenMasternodeBroadcast[hash].first = GetTime();
                masternodeSync.BumpAssetLastTime("CMasternodeMan::CheckMnbAndUpdateMasternodeList - seen");
            }
            // did we ask this node for it?
            if(pfrom && IsMnbRecoveryRequested(hash) && GetTime() < mMnbRecoveryRequests[hash].first) {
                LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- mnb=%s seen request\n", hash.ToString());
                if(mMnbRecoveryRequests[hash].second.count(pfrom->addr)) {
                    LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- mnb=%s seen request, addr=%s\n", hash.ToString(), pfrom->addr.ToString());
                    // do not allow node to send same mnb multiple times in recovery mode
                    mMnbRecoveryRequests[hash].second.erase(pfrom->addr);
                    // does it have newer lastPing?
                    if(mnb.lastPing.sigTime > mapSeenMasternodeBroadcast[hash].second.lastPing.sigTime) {
                        // simulate Check
                        CMasternode mnTemp = CMasternode(mnb);
                        mnTemp.Check();
                        LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- mnb=%s seen request, addr=%s, better lastPing: %d min ago, projected mn state: %s\n", hash.ToString(), pfrom->addr.ToString(), (GetAdjustedTime() - mnb.lastPing.sigTime)/60, mnTemp.GetStateString());
                        if(mnTemp.IsValidStateForAutoStart(mnTemp.nActiveState)) {
                            // this node thinks it's a good one
                            LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s seen good\n", mnb.outpoint.ToString());
                            mMnbRecoveryGoodReplies[hash].push_back(mnb);
                        }
                    }
                }
            }
            return true;
        }
        mapSeenMasternodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));

        LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s new\n", mnb.outpoint.ToString());

        if(!mnb.SimpleCheck(nDos)) {
            LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- SimpleCheck() failed, masternode=%s\n", mnb.outpoint.ToString());
            return false;
        }

        // search Masternode list
        CMasternode* pmn = Find(mnb.outpoint);
        if(pmn) {
            CMasternodeBroadcast mnbOld = mapSeenMasternodeBroadcast[CMasternodeBroadcast(*pmn).GetHash()].second;
            if(!mnb.Update(pmn, nDos, connman)) {
                LogPrint(BCLog::MN, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- Update() failed, masternode=%s\n", mnb.outpoint.ToString());
                return false;
            }
            if(hash != mnbOld.GetHash()) {
                mapSeenMasternodeBroadcast.erase(mnbOld.GetHash());
            }
            return true;
        }
    }

    if(mnb.CheckOutpoint(nDos)) {
        Add(mnb);
        masternodeSync.BumpAssetLastTime("CMasternodeMan::CheckMnbAndUpdateMasternodeList - new");
        // if it matches our Masternode privkey...
        if(fMasternodeMode && mnb.pubKeyMasternode == activeMasternode.pubKeyMasternode) {
            mnb.nPoSeBanScore = -MASTERNODE_POSE_BAN_MAX_SCORE;
            if(mnb.nProtocolVersion == PROTOCOL_VERSION) {
                // ... and PROTOCOL_VERSION, then we've been remotely activated ...
                LogPrintf("CMasternodeMan::CheckMnbAndUpdateMasternodeList -- Got NEW Masternode entry: masternode=%s  sigTime=%lld  addr=%s\n",
                            mnb.outpoint.ToString(), mnb.sigTime, mnb.addr.ToString());
                activeMasternode.ManageState(connman);
            } else {
                // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
                // but also do not ban the node we get this message from
                LogPrintf("CMasternodeMan::CheckMnbAndUpdateMasternodeList -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", mnb.nProtocolVersion, PROTOCOL_VERSION);
                return false;
            }
        }
        mnb.Relay(connman);
    } else {
        LogPrintf("CMasternodeMan::CheckMnbAndUpdateMasternodeList -- Rejected Masternode entry: %s  addr=%s\n", mnb.outpoint.ToString(), mnb.addr.ToString());
        return false;
    }

    return true;
}

void CMasternodeMan::UpdateLastSentinelPingTime()
{
    LOCK(cs);
    nLastSentinelPingTime = GetTime();
}

bool CMasternodeMan::IsSentinelPingActive()
{
    LOCK(cs);
    // Check if any masternodes have voted recently, otherwise return false
    return (GetTime() - nLastSentinelPingTime) <= MASTERNODE_SENTINEL_PING_MAX_SECONDS;
}

void CMasternodeMan::CheckMasternode(const CPubKey& pubKeyMasternode, bool fForce)
{
    LOCK2(cs_main, cs);
    for (auto& mnpair : mapMasternodes) {
        if (mnpair.second.pubKeyMasternode == pubKeyMasternode) {
            mnpair.second.Check(fForce);
            return;
        }
    }
}

bool CMasternodeMan::IsMasternodePingedWithin(const COutPoint& outpoint, int nSeconds, int64_t nTimeToCheckAt)
{
    LOCK(cs);
    CMasternode* pmn = Find(outpoint);
    return pmn ? pmn->IsPingedWithin(nSeconds, nTimeToCheckAt) : false;
}

void CMasternodeMan::SetMasternodeLastPing(const COutPoint& outpoint, const CMasternodePing& mnp)
{
    LOCK(cs);
    CMasternode* pmn = Find(outpoint);
    if(!pmn) {
        return;
    }
    pmn->lastPing = mnp;
    if(mnp.fSentinelIsCurrent) {
        UpdateLastSentinelPingTime();
    }
    mapSeenMasternodePing.insert(std::make_pair(mnp.GetHash(), mnp));

    CMasternodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if(mapSeenMasternodeBroadcast.count(hash)) {
        mapSeenMasternodeBroadcast[hash].second.lastPing = mnp;
    }
}

void CMasternodeMan::UpdatedBlockTip(const CBlockIndex *pindex)
{
    nCachedBlockHeight = pindex->nHeight;
    LogPrint(BCLog::MN, "CMasternodeMan::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    CheckSameAddr();

    // update payment info
    if (masternodeSync.IsSynced()) {
        ForEach([](CMasternode& mn) {
            int save = mn.nBlockLastPaid;
            mn.nBlockLastPaid = votes.get_payheight (mn.pubKeyCollateralAddress.GetID());
            if (save != mn.nBlockLastPaid) {
                const CBlockIndex* pi = chainActive[mn.nBlockLastPaid];
                if (pi) mn.nTimeLastPaid = pi->nTime;
                LogPrint(BCLog::MN, "Masternode: found payment to %s in height %d\n", mn.outpoint.ToString(), mn.nBlockLastPaid);
            }
            return true;
        });
    }
}

void CMasternodeMan::WarnMasternodeDaemonUpdates()
{
    LOCK(cs);

    static bool fWarned = false;

    if (fWarned || !size() || !masternodeSync.IsMasternodeListSynced())
        return;

    int nUpdatedMasternodes{0};

    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.lastPing.nDaemonVersion > CLIENT_VERSION) {
            ++nUpdatedMasternodes;
        }
    }

    // Warn only when at least half of known masternodes already updated
    if (nUpdatedMasternodes < size() / 2)
        return;

    std::string strWarning;
    if (nUpdatedMasternodes != size()) {
        strWarning = strprintf(_("Warning: At least %d of %d masternodes are running on a newer software version. Please check latest releases, you might need to update too."),
                    nUpdatedMasternodes, size());
    } else {
        // someone was postponing this update for way too long probably
        strWarning = strprintf(_("Warning: Every masternode (out of %d known ones) is running on a newer software version. Please check latest releases, it's very likely that you missed a major/critical update."),
                    size());
    }

    // notify GetWarnings(), called by Qt and the JSON-RPC code to warn the user
    SetMiscWarning(strWarning);

    fWarned = true;
}

void CMasternodeMan::NotifyMasternodeUpdates(CConnman& connman)
{
    // Avoid double locking
    bool fMasternodesAddedLocal = false;
    bool fMasternodesRemovedLocal = false;
    {
        LOCK(cs);
        fMasternodesAddedLocal = fMasternodesAdded;
        fMasternodesRemovedLocal = fMasternodesRemoved;
    }

    LOCK(cs);
    fMasternodesAdded = false;
    fMasternodesRemoved = false;
    uiInterface.NotifyMasternodeListChanged();
}

void CMasternodeMan::Dump (const std::string& border, std::function<void(std::string)> dumpfunc) {
    LOCK(cs);
    dumpfunc (border + "masternode {");
    for (auto& mnpair : mapMasternodes)
        mnpair.second.Dump(border + "    ", dumpfunc);
    dumpfunc (border + "}");
    dumpfunc ("");
    dumpfunc (border + "mAskedUsForMasternodeList {");
    for (const auto& item : mAskedUsForMasternodeList)
        dumpfunc (border + "    " + item.first.ToString() + " - " + EasyFormatDateTime(item.second));
    dumpfunc (border + "}");
    dumpfunc ("");
    dumpfunc (border + "mWeAskedForMasternodeList {");
    for (const auto& item : mWeAskedForMasternodeList)
        dumpfunc (border + "    " + item.first.ToString() + " - " + EasyFormatDateTime(item.second));
    dumpfunc (border + "}");
    dumpfunc ("");
    dumpfunc (border + "mWeAskedForMasternodeListEntry {");
    for (const auto& item : mWeAskedForMasternodeListEntry) {
        dumpfunc (border + "    " + item.first.ToString() + ": ");// + EasyFormatDateTime((item.second));
        for (auto& item2 : item.second)
            dumpfunc (border + "        " + item2.first.ToString() + " - " + EasyFormatDateTime(item2.second));
    }
    dumpfunc (border + "}");
    dumpfunc ("");
    dumpfunc (border + "_mWeAskedForVerification {");
    for (const auto& item : mWeAskedForVerification)
        dumpfunc (border + "    " + item.first.ToString() + " - " + item.second.masternodeOutpoint1.ToString() + " - " +
                    item.second.masternodeOutpoint2.ToString() + " - " + item.second.addr.ToString());
    dumpfunc (border + "}");
    dumpfunc ("");
    dumpfunc (border + "mMnbRecoveryRequests {");
    for (const auto& item : mMnbRecoveryRequests) {
        std::string nfo;
        for (const auto& item2 : item.second.second) nfo += item2.ToString() + ", ";
        dumpfunc (border + "    " + HexStr(item.first) + " - " + EasyFormatDateTime(item.second.first) + " - " + nfo);
    }
    dumpfunc (border + "}");
    dumpfunc ("");
    dumpfunc (border + "mMnbRecoveryGoodReplies {");
    for (auto& item : mMnbRecoveryGoodReplies) {
        dumpfunc (border + "    " + HexStr(item.first) + ": ");
        for (auto& item2 : item.second)
            item2.Dump(border + "    ", dumpfunc);
    }
    dumpfunc (border + "}");
    dumpfunc ("");
    dumpfunc (border + "_listScheduledMnbRequestConnections {");
    for (const auto& item : listScheduledMnbRequestConnections)
        dumpfunc (border + "    " + item.first.ToString() + " - " + HexStr(item.second));
    dumpfunc (border + "}");
    dumpfunc ("");
    dumpfunc (border + "mapSeenMasternodeBroadcast {");
    for (const auto& item : mapSeenMasternodeBroadcast)
        dumpfunc (border + "    " + HexStr(item.first) + " - " + EasyFormatDateTime(item.second.first) + " - " +
                    item.second.second.outpoint.ToString());
    dumpfunc (border + "}");
    dumpfunc ("");
    dumpfunc (border + "mapSeenMasternodePing {");
    for (const auto& item : mapSeenMasternodePing)
        dumpfunc (border + "    " + HexStr(item.first) + " - " + EasyFormatDateTime(item.second.sigTime) + " - " +
            item.second.masternodeOutpoint.ToString());
    dumpfunc (border + "}");
    
    dumpfunc ("");
    dumpfunc (border + "mapSeenMasternodeVerification {");
    for (const auto& item : mapSeenMasternodeVerification)
        dumpfunc (border + "    " + HexStr(item.first) + " - " + item.second.masternodeOutpoint1.ToString() + " - " +
                    item.second.masternodeOutpoint2.ToString() + " - " + item.second.addr.ToString());
    dumpfunc (border + "}");
    dumpfunc (border + "nDsqCount = " + itostr(nDsqCount));
}

// masternodeconfig

void CMasternodeConfig::add(const std::string& alias, const std::string& ip, const std::string& privKey, const std::string& txHash, const std::string& outputIndex) {
    CMasternodeEntry cme(alias, ip, privKey, txHash, outputIndex);
    entries.push_back(cme);
}

bool CMasternodeConfig::read(std::string& strErrRet) {
    int linenumber = 1;
    boost::filesystem::path pathMasternodeConfigFile = GetMasternodeConfigFile();
    boost::filesystem::ifstream streamConfig(pathMasternodeConfigFile);

    if (!streamConfig.good()) {
        return true; // Nothing to read, so just return
    }

    for(std::string line; std::getline(streamConfig, line); linenumber++)
    {
        if(line.empty()) continue;

        std::istringstream iss(line);
        std::string comment, alias, ip, privKey, txHash, outputIndex;

        if (iss >> comment) {
            if(comment.at(0) == '#') continue;
            iss.str(line);
            iss.clear();
        }

        if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
            iss.str(line);
            iss.clear();
            if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
                strErrRet = _("Could not parse masternode.conf") + "\n" +
                        strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
                streamConfig.close();
                return false;
            }
        }

        int port = 0;
        std::string hostname = "";
        SplitHostPort(ip, port, hostname);
        if(port == 0 || hostname == "") {
            strErrRet = _("Failed to parse host:port string") + "\n"+
                    strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
            streamConfig.close();
            return false;
        }
        add(alias, ip, privKey, txHash, outputIndex);
    }

    streamConfig.close();
    return true;
}

bool CMasternodeConfig::write(std::string& strErrRet) {
    fs::path pathMasternodeConfigFile = GetMasternodeConfigFile();
    fs::path pathMasternodeConfigFileBak = pathMasternodeConfigFile;
    pathMasternodeConfigFileBak += ".bak";
    if (fs::exists(pathMasternodeConfigFileBak)) remove(pathMasternodeConfigFileBak);
    RenameOver(pathMasternodeConfigFile, pathMasternodeConfigFileBak);
    remove(pathMasternodeConfigFile);
    fs::ofstream streamConfig(pathMasternodeConfigFile);
    streamConfig << "# Masternode config file\n" <<
                    "# Format: alias IP:port masternodeprivkey collateral_output_txid collateral_output_index\n";
    for (const auto& mne : entries) {
        streamConfig << mne.getAlias() << " " << mne.getIp() << " " << mne.getPrivKey() << " " << 
                    mne.getTxHash() << " " << mne.getOutputIndex() << "\n";
    }
    return true;
}

void load_mn_dat () {
    int64_t nStart = GetTimeMillis();
    fs::path pathDB = GetDataDir() / "masternode.dat";
    FILE *file = fopen(pathDB.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        LogPrintf("masternode.dat: Failed to open file\n");
    } else {
        int dataSize = fs::file_size(pathDB) - sizeof(uint256);
        if (dataSize < 0) dataSize = 0;
        std::vector<unsigned char> vchData;
        vchData.resize(dataSize);
        uint256 hashIn;
        try {
            filein.read((char *)vchData.data(), dataSize);
            filein >> hashIn;
        }
        catch (std::exception &e) {
            LogPrintf("masternode.dat: Serialize or I/O error - %s\n", e.what());
        }
        filein.fclose();
        CDataStream ssObj(vchData, SER_DISK, CLIENT_VERSION);
        uint256 hashTmp = Hash(ssObj.begin(), ssObj.end());
        if (hashIn != hashTmp) {
            LogPrintf("masternode.dat: Checksum mismatch, data corrupted\n");
        } else {
            unsigned char pchMsgTmp[4];
            try {
                ssObj >> pchMsgTmp;
                if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp))) {
                    LogPrintf("masternode.dat: Invalid network magic number\n");
                } else {
                    ssObj >> mnodeman;
                    ssObj >> mnpayments;
                }
            }
            catch (std::exception &e) {
                mnodeman.Clear();
                mnpayments.Clear();
                LogPrintf("masternode.dat: Serialize or I/O error - %s\n", e.what());
            }
            catch (...) {
                mnodeman.Clear();
                mnpayments.Clear();
                LogPrintf("masternode.dat: Serialize or I/O error\n");
            }
        }
        LogPrintf("masternode.dat: load finished  %dms\n", GetTimeMillis() - nStart);
    }
}

void save_mn_dat () {
    int64_t nStart = GetTimeMillis();
    CDataStream ssObj(SER_DISK, CLIENT_VERSION);
    ssObj << Params().MessageStart() << mnodeman << mnpayments;
    uint256 hash = Hash(ssObj.begin(), ssObj.end());
    ssObj << hash;
    fs::path pathDB = GetDataDir() / "masternode.dat";
    FILE *file = fopen(pathDB.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        LogPrintf("masternode.dat: Failed to open file\n");
    } else {
        try {
            fileout << ssObj;
        }
        catch (std::exception &e) {
            LogPrintf("masternode.dat: Serialize or I/O error - %s\n", e.what());
        }
        catch (...) {
            LogPrintf("masternode.dat: Serialize or I/O error\n");
        }
        fileout.fclose();
    }
    LogPrintf("masternode.dat: dump finished  %dms\n", GetTimeMillis() - nStart);
}

CMasternodeConfig masternodeConfig;

fs::path GetMasternodeConfigFile()
{
    fs::path pathConfigFile(gArgs.GetArg("-mnconf", "masternode.conf"));
    if (!pathConfigFile.is_complete())
        pathConfigFile = GetDataDir() / pathConfigFile;
    return pathConfigFile;
}

// activemasternode

void CActiveMasternode::ManageState(CConnman& connman)
{
    LogPrint(BCLog::MN, "CActiveMasternode::ManageState -- Start\n");
    if (!fMasternodeMode) {
        LogPrint(BCLog::MN, "CActiveMasternode::ManageState -- Not a masternode, returning\n");
        return;
    }

    if (!masternodeSync.IsBlockchainSynced()) {
        nState = ACTIVE_MASTERNODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveMasternode::ManageState -- %s: %s\n", GetStateString(), GetStatus());
        return;
    }

    if (nState == ACTIVE_MASTERNODE_SYNC_IN_PROCESS) {
        nState = ACTIVE_MASTERNODE_INITIAL;
    }

    LogPrint(BCLog::MN, "CActiveMasternode::ManageState -- status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);

    if (eType == MASTERNODE_UNKNOWN) {
        ManageStateInitial(connman);
    }

    if (eType == MASTERNODE_REMOTE) {
        ManageStateRemote();
    }

    SendMasternodePing(connman);
}

std::string CActiveMasternode::GetStateString() const
{
    switch (nState) {
        case ACTIVE_MASTERNODE_INITIAL:         return "INITIAL";
        case ACTIVE_MASTERNODE_SYNC_IN_PROCESS: return "SYNC_IN_PROCESS";
        case ACTIVE_MASTERNODE_INPUT_TOO_NEW:   return "INPUT_TOO_NEW";
        case ACTIVE_MASTERNODE_NOT_CAPABLE:     return "NOT_CAPABLE";
        case ACTIVE_MASTERNODE_STARTED:         return "STARTED";
        default:                                return "UNKNOWN";
    }
}

std::string CActiveMasternode::GetStatus() const
{
    switch (nState) {
        case ACTIVE_MASTERNODE_INITIAL:         return "Node just started, not yet activated";
        case ACTIVE_MASTERNODE_SYNC_IN_PROCESS: return "Sync in progress. Must wait until sync is complete to start Masternode";
        case ACTIVE_MASTERNODE_INPUT_TOO_NEW:   return strprintf("Masternode input must have at least 12 confirmations");
        case ACTIVE_MASTERNODE_NOT_CAPABLE:     return "Not capable masternode: " + strNotCapableReason;
        case ACTIVE_MASTERNODE_STARTED:         return "Masternode successfully started";
        default:                                return "Unknown";
    }
}

std::string CActiveMasternode::GetTypeString() const
{
    std::string strType;
    switch(eType) {
    case MASTERNODE_REMOTE:
        strType = "REMOTE";
        break;
    default:
        strType = "UNKNOWN";
        break;
    }
    return strType;
}

bool CActiveMasternode::DoAnnounce (CConnman& connman, std::string& strError) {
    CMasternodeBroadcast mnb;
    bool fResult = CMasternodeBroadcast::Create(service.ToString(), EncodeSecret(activeMasternode.keyMasternode),
                outpoint.hash.ToString(), itostr(outpoint.n), strError, mnb);
    int nDoS;
    if (fResult && !mnodeman.CheckMnbAndUpdateMasternodeList (nullptr, mnb, nDoS, connman)) {
        strError = "Failed to verify MNB";
        fResult = false;
    }
    return fResult;
}

bool CActiveMasternode::SendMasternodePing(CConnman& connman)
{
    if (!mnodeman.Has(outpoint)) {
        std::string strError;
        if (!DoAnnounce (connman, strError)) {
            nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
            LogPrintf("CActiveMasternode::SendMasternodePing -- %s: %s\n", GetStateString(), strError + "(not in masternode list)");
            return false;
        }
    }

    if (!fPingerEnabled) {
        LogPrint(BCLog::MN, "CActiveMasternode::SendMasternodePing -- %s: masternode ping service is disabled, skipping...\n", GetStateString());
        return false;
    }

    CMasternodePing mnp(outpoint);
    mnp.nSentinelVersion = nSentinelVersion;
    mnp.fSentinelIsCurrent =
            (abs(GetAdjustedTime() - nSentinelPingTime) < MASTERNODE_SENTINEL_PING_MAX_SECONDS);
    if(!mnp.Sign(keyMasternode, pubKeyMasternode)) {
        LogPrintf("CActiveMasternode::SendMasternodePing -- ERROR: Couldn't sign Masternode Ping\n");
        return false;
    }

    // Update lastPing for our masternode in Masternode list
    if(mnodeman.IsMasternodePingedWithin(outpoint, MASTERNODE_MIN_MNP_SECONDS, mnp.sigTime)) {
        LogPrintf("CActiveMasternode::SendMasternodePing -- Too early to send Masternode Ping\n");
        return false;
    }

    mnodeman.SetMasternodeLastPing(outpoint, mnp);

    LogPrintf("CActiveMasternode::SendMasternodePing -- Relaying ping, collateral=%s\n", outpoint.ToString());
    mnp.Relay(connman);

    return true;
}

bool CActiveMasternode::UpdateSentinelPing(int version)
{
    nSentinelVersion = version;
    nSentinelPingTime = GetAdjustedTime();

    return true;
}

void CActiveMasternode::ManageStateInitial(CConnman& connman)
{
    LogPrint(BCLog::MN, "CActiveMasternode::ManageStateInitial -- status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);

    // Check that our local network configuration is correct
    if (!fListen) {
        // listen option is probably overwritten by smth else, no good
        nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
        strNotCapableReason = "Masternode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        LogPrintf("CActiveMasternode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // First try to find whatever local address is specified by externalip option
    bool fFoundLocal = GetLocal(service) && CMasternode::IsValidNetAddr(service);
    if (!fFoundLocal) {
        bool empty = true;
        // If we have some peers, let's try to find our local address from one of them
        connman.ForEachNode([&fFoundLocal, &empty, this](CNode* pnode) {
            empty = false;
            if (pnode->addr.IsIPv4())
                fFoundLocal = GetLocal(service, &pnode->addr) && CMasternode::IsValidNetAddr(service);
            return !fFoundLocal;
        });
        // nothing and no live connections, can't do anything for now
        if (empty) {
            nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
            strNotCapableReason = "Can't detect valid external address. Will retry when there are some connections available.";
            LogPrintf("CActiveMasternode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    }

    if (!fFoundLocal) {
        nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
        strNotCapableReason = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
        LogPrintf("CActiveMasternode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    if(service.GetPort() != Params().GetDefaultPort()) {
        nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
        strNotCapableReason = strprintf("Invalid port: %u - only %d is supported on mainnet.", 
                    service.GetPort(), Params().GetDefaultPort());
        LogPrintf("CActiveMasternode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // Check socket connectivity
    LogPrintf("CActiveMasternode::ManageStateInitial -- Checking inbound connection to '%s'\n", service.ToString());
    SOCKET hSocket = CreateSocket(service);
    bool fConnected = ConnectSocketDirectly(service, hSocket, nConnectTimeout, true) && IsSelectableSocket(hSocket);
    CloseSocket(hSocket);

    if (!fConnected) {
        nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
        strNotCapableReason = "Could not connect to " + service.ToString();
        LogPrintf("CActiveMasternode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // Default to REMOTE
    eType = MASTERNODE_REMOTE;

    LogPrint(BCLog::MN, "CActiveMasternode::ManageStateInitial -- End status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);
}

void CActiveMasternode::ManageStateRemote()
{
    LogPrint(BCLog::MN, "CActiveMasternode::ManageStateRemote -- Start status = %s, type = %s, pinger enabled = %d, pubKeyMasternode.GetID() = %s\n", 
             GetStatus(), GetTypeString(), fPingerEnabled, pubKeyMasternode.GetID().ToString());

    mnodeman.CheckMasternode(pubKeyMasternode, true);
    CMasternodeBase infoMn;
    if (mnodeman.GetMasternodeInfo(pubKeyMasternode, infoMn)) {
        if (infoMn.nProtocolVersion != PROTOCOL_VERSION) {
            nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
            strNotCapableReason = "Invalid protocol version";
            LogPrintf("CActiveMasternode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (service != infoMn.addr) {
            nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
            strNotCapableReason = "Broadcasted IP doesn't match our external address. Make sure you issued a new broadcast if IP of this masternode changed recently.";
            LogPrintf("CActiveMasternode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (!CMasternode::IsValidStateForAutoStart(infoMn.nActiveState)) {
            nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Masternode in %s state", CMasternode::StateToString(infoMn.nActiveState));
            LogPrintf("CActiveMasternode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (nState != ACTIVE_MASTERNODE_STARTED) {
            LogPrintf("CActiveMasternode::ManageStateRemote -- STARTED!\n");
            outpoint = infoMn.outpoint;
            service = infoMn.addr;
            fPingerEnabled = true;
            nState = ACTIVE_MASTERNODE_STARTED;
        }
    }
    else {
        nState = ACTIVE_MASTERNODE_NOT_CAPABLE;
        strNotCapableReason = "Masternode not in masternode list";
        LogPrintf("CActiveMasternode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
    }
}

CActiveMasternode activeMasternode;

bool fMasternodeMode = false;

// messagesigner

bool CMessageSigner::GetKeysFromSecret(const std::string& strSecret, CKey& keyRet, CPubKey& pubkeyRet)
{
    keyRet = DecodeSecret (strSecret); 
    if(!keyRet.IsValid()) return false;

    pubkeyRet = keyRet.GetPubKey();
    return true;
}

bool CMessageSigner::SignMessage(const std::string& strMessage, std::vector<unsigned char>& vchSigRet, const CKey& key)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    return key.SignCompact(ss.GetHash(), vchSigRet);
}

bool CMessageSigner::VerifyMessage(const CPubKey& pubkey, const std::vector<unsigned char>& vchSig, const std::string& strMessage, std::string& strErrorRet)
{
    return VerifyMessage(pubkey.GetID(), vchSig, strMessage, strErrorRet);
}

bool CMessageSigner::VerifyMessage(const CKeyID& keyID, const std::vector<unsigned char>& vchSig, const std::string& strMessage, std::string& strErrorRet)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkeyFromSig;
    if (!pubkeyFromSig.RecoverCompact(ss.GetHash(), vchSig)) {
        strErrorRet = "Error recovering public key.";
        return false;
    }

    if (pubkeyFromSig.GetID() != keyID) {
        strErrorRet = strprintf("Keys don't match: pubkey=%s, pubkeyFromSig=%s", keyID.ToString(),
                    pubkeyFromSig.GetID().ToString());
        return false;
    }
    return true;
}

// netfulfilledman

CNetFulfilledRequestManager netfulfilledman;

void CNetFulfilledRequestManager::AddFulfilledRequest(const CService& addr, const std::string& strRequest) {
    LOCK(cs_mapFulfilledRequests);
    mapFulfilledRequests[addr.ToString() + strRequest] = GetTime() + 15 * 60;
}

bool CNetFulfilledRequestManager::HasFulfilledRequest(const CService& addr, const std::string& strRequest) {
    LOCK(cs_mapFulfilledRequests);
    auto it = mapFulfilledRequests.find (addr.ToString() + strRequest);
    return (it != mapFulfilledRequests.end()) && (it->second > GetTime());
}

void CNetFulfilledRequestManager::RemoveFulfilledRequest(const CService& addr, const std::string& strRequest) {
    LOCK(cs_mapFulfilledRequests);
    mapFulfilledRequests.erase (addr.ToString() + strRequest);
}

void CNetFulfilledRequestManager::CheckAndRemove() {
    LOCK(cs_mapFulfilledRequests);

    int64_t now = GetTime();
    auto it = mapFulfilledRequests.begin();
    while (it != mapFulfilledRequests.end()) {
        if (now > it->second) {
            mapFulfilledRequests.erase(it++);
        } else {
            ++it;
        }
    }
}

void CNetFulfilledRequestManager::Clear() {
    LOCK(cs_mapFulfilledRequests);
    mapFulfilledRequests.clear();
}

std::string CNetFulfilledRequestManager::ToString() const {
    std::ostringstream info;
    info << "Nodes with fulfilled requests: " << (int)mapFulfilledRequests.size();
    return info.str();
}

// dsnotificationinterface

void CDSNotificationInterface::InitializeCurrentBlockTip()
{
    LOCK(cs_main);
    UpdatedBlockTip(chainActive.Tip(), nullptr, IsInitialBlockDownload());
}

void CDSNotificationInterface::NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload)
{
    masternodeSync.NotifyHeaderTip(pindexNew, fInitialDownload, connman);
}

void CDSNotificationInterface::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload)
{
    if (pindexNew == pindexFork) // blocks were disconnected without any new ones
        return;

    masternodeSync.UpdatedBlockTip(pindexNew, fInitialDownload, connman);

    if (fInitialDownload)
        return;
    if (pindexNew->nHeight < Params().GetConsensus().nMasternodePaymentsStartBlock) {
        fMasternodeMode = false;
        return;
    }

    mnodeman.UpdatedBlockTip(pindexNew);
    mnpayments.UpdatedBlockTip(pindexNew, connman);
    votes.UpdatedBlockTip (pindexNew);
}

void CDSNotificationInterface::BlockConnected (const std::shared_ptr<const CBlock> &pblock, const CBlockIndex *pindex,
    const std::vector<CTransactionRef> &vtxConflicted)
{
    votes.BlockConnected(pblock, pindex);
}

// newest protect

bool IsValidAddr (const CService& addr) {
    return (addr.IsIPv4() || addr.IsIPv6()) && IsReachable(addr) && addr.IsRoutable();
}

bool CVote::check () {
    if ((state & 1) == 0) {
        if (IsInitialBlockDownload()) return false;
        state |= 1;
    }

    CBlockIndex* pindex = LookupBlockIndex (block_hash);
    if (!pindex || (pindex->nHeight != block_height)) return false;

    if ((state & 2) == 0) {
        if (!IsValidAddr(addr)) return false;
        state |= 2;
    }

    if ((state & 4) == 0) {
        if ((verify_addr != CService()) && !IsValidAddr(verify_addr)) return false;
        state |= 4;
    }

    if ((state & 8) == 0) {
        CPubKey pk;
        if (!pk.RecoverCompact(hash(), sig)) return false;
        if (pk.GetID() != reward) return false;
        state |= 8;
    }

    return true;
}

bool CVote::sign () {
    if (!votes.key.IsValid()) return false;
    if (!votes.key.SignCompact(hash(), sig)) return false;

    return true;
}

void CVote::dump (const std::string& border, std::function<void(std::string)> dumpfunc) {
    dumpfunc(border + hash().ToString() + " {");
    dumpfunc(border + "    address = " + addr.ToString());
    dumpfunc(border + "    block_hash = " + block_hash.ToString());
    dumpfunc(border + "    block_height = " + itostr(block_height));
    dumpfunc(border + "    verify_addr = " + verify_addr.ToString());
    dumpfunc(border + "    reward = " + EncodeDestination(reward));
    dumpfunc(border + "}");
}

bool CVotes::exist (const uint256& hash) {
    LOCK (cs);
    return (mapVotes.count(hash) != 0) || (mapUnchecked.count(hash) != 0);
}

void CVotes::add (const uint256& hash, CVote& vote) {
    if (exist(hash)) return;
    LOCK (cs);
    if (vote.check()) {
        mapVotes[hash] = vote;
        auto hh = std::make_pair(vote.block_height, vote.block_hash);
        auto nid = std::make_pair(vote.addr, vote.reward);
        cacheVoting[hh].insert(nid);
        cacheNodes[nid].second = hh;
        if (vote.verify_addr != CService()) {
            auto vid = std::make_pair(vote.verify_addr, CKeyID());
            cacheVerify[vid][nid] = hh;
        }
        g_connman->ForEachNode([&vote](CNode* pnode) {
            CNetMsgMaker msgMaker(pnode->GetSendVersion());
            g_connman->PushMessage(pnode, msgMaker.Make("vote", vote));
        });
    } else {
        mapUnchecked[hash] = vote;
    }
}

void CVotes::UpdatedBlockTip (const CBlockIndex *pindex) {
    int height = pindex ? pindex->nHeight : chainActive.Height();
    {
        LOCK (cs);
        static int tick = -1;
        if (tick++ > 24) {
            tick = 0;
            auto it1 = mapVotes.begin();
            while (it1 != mapVotes.end()) {
                if (height - it1->second.block_height < 2016) { ++it1; continue; }
                it1 = mapVotes.erase (it1);
            }
            auto it2 = mapUnchecked.begin();
            while (it2 != mapUnchecked.end()) {
                if (height - it2->second.block_height < 2016) { ++it2; continue; }
                it2 = mapUnchecked.erase (it2);
            }
            auto it3 = cacheVoting.begin();
            while (it3 != cacheVoting.end()) {
                if (height - it3->first.first < 2016) { ++it3; continue; }
                it3 = cacheVoting.erase (it3);
            }
            auto it4 = cacheNodes.begin();
            while (it4 != cacheNodes.end()) {
                if (height - it4->second.second.first < 2016) { ++it4; continue; }
                it4 = cacheNodes.erase (it4);
            }
            auto it5 = cacheVerify.begin();
            while (it5 != cacheVerify.end()) {
                if (cacheNodes.count(it5->first) > 0) { ++it5; continue; }
                it5 = cacheVerify.erase (it5);
            }
        }
    }
    if (IsValidAddr(netaddr)) {
        if (!key.IsValid()) {
            std::vector<unsigned char> data;
            if (pblocktree->ReadKey (0, data)) key.Set(data.begin(), data.end(), true);
            if (!key.IsValid()) {
                key.MakeNewKey (true);
                data.clear();
                data.insert(data.end(), key.begin(), key.end());
                if (!pblocktree->WriteKey (0, data)) key = CKey();
            }
            if (key.IsValid()) LogPrintf("Detected public address - %s\n", EncodeDestination(key.GetPubKey().GetID()));
        }
        if (!pubkey.IsValid() && key.IsValid()) pubkey = key.GetPubKey();
        if (key.IsValid() && pubkey.IsValid()) {
            CVote newvote;
            newvote.addr = netaddr;
            newvote.block_height = height - 24;
            if (!GetBlockHash(newvote.block_hash, newvote.block_height)) return;
            newvote.verify_addr = CService();                               // TO DO
            newvote.reward = pubkey.GetID();
            newvote.sign ();
            if (newvote.check()) {
                votes.add (newvote.hash(), newvote);
            }
        }
    } else {
        bool fFound = GetLocal(netaddr) && IsValidAddr(netaddr);
        if (!fFound) {
            g_connman->ForEachNode([&](CNode* pnode) {
                if (pnode->addr.IsIPv4() || pnode->addr.IsIPv6())
                    fFound = GetLocal(netaddr, &pnode->addr) && IsValidAddr(netaddr);
                return !fFound;
            });
        }
        if (fFound) LogPrintf("Detected public IP - %s\n", netaddr.ToString());
    }
}

bool CVotes::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv) {
    if (strCommand == "vote") {
        CVote vote;
        vRecv >> vote;
        add (vote.hash(), vote);
        return true;
    }
    return false;
}

void CVotes::BlockConnected (const std::shared_ptr<const CBlock> &pblock, const CBlockIndex *pindex) {
    update_pay (pblock->GetHash(), pindex->nHeight, *(pblock->vtx[0]));
}

void CVotes::update_pay (const uint256 &block_hash, int height, const CTransaction &tx) {
    if (IsInitialBlockDownload()) return;
    LOCK (cs_pay);
    CAmount nPayment = (tx.GetValueOut() * Params().GetConsensus().nMasternodePaymentsPercent) / 100;
    for (const auto& txout : tx.vout) {
        if (nPayment != txout.nValue) continue;
        std::vector<std::vector<unsigned char>> vSolutions;
        txnouttype whichType;
        Solver (txout.scriptPubKey, whichType, vSolutions);
        if (whichType == TX_PUBKEY) {
            CPubKey pubKey(vSolutions[0]);
            if (!pubKey.IsValid()) continue;
            mapPayouts[std::make_pair(height, block_hash)] = pubKey.GetID();
        } else if (whichType == TX_PUBKEYHASH) {
            mapPayouts[std::make_pair(height, block_hash)] = CKeyID(uint160(vSolutions[0]));
        }
    }
}

int CVotes::get_payheight (const CKeyID &addr) {
    if (IsInitialBlockDownload()) return 0;
    int curr = chainActive.Height();
    if (curr < Params().GetConsensus().nMasternodePaymentsStartBlock) return 0;
    static int last = -1;
    LOCK (cs_pay);
    if (last < 0) {
        last = curr;
        CBlockIndex* tip = chainActive.Tip();
        int nb = std::max ((int)cacheNodes.size() * 5, 100);
        while ((nb-- > 0) && tip) {
            CBlock block;
            if (ReadBlockFromDisk(block, tip, Params().GetConsensus()))
                update_pay (tip->GetBlockHash(), tip->nHeight, *block.vtx[0]);
            tip = tip->pprev;
        }
    }
    if (curr - last > 16) {
        last = curr;
        int nb = std::max ((int)cacheNodes.size() * 10, 100);
        auto it = mapPayouts.begin();
        while (it != mapPayouts.end())
            if (curr - it->first.first > nb) { it = mapPayouts.erase(it); } else { ++it; }
    }
    int height = 0;
    for (const auto& it : mapPayouts) {
        if ((it.second == addr) && (it.first.first > height)) {
            CBlockIndex* bi = chainActive[it.first.first];
            if (bi && (bi->GetBlockHash() == it.first.second)) height = it.first.first;
        }
    }
    return height;
}

uint256 CVotes::calc_blockhash (int block_height) {
    int curr = chainActive.Height() - block_height;
    uint256 hash{};
    int cnt = 0;
    if ((curr > 120) || (curr < -12)) return hash;
    LOCK (cs);
    for (const auto& it : cacheVoting) {
        if ((it.first.first == block_height) && (it.second.size() > cnt)) {
            hash = it.first.second;
            cnt = it.second.size();
        }
    }
    return hash;
}

CKeyID CVotes::calc_payaddr (int block_height) {
    int chei = chainActive.Height();
    int curr = chei - block_height;
    if ((curr > 120) || (curr < -24)) return CKeyID();
    if (curr > 0) {
        LOCK (cs_pay);
        for (const auto& it : mapPayouts) {
            if (block_height == it.first.first) return it.second;
        }
        return CKeyID();
    }
    LOCK (cs);
    std::vector<std::pair<int, CKeyID>> vecPayes;
    for (const auto& it : cacheNodes) {
        if (chei - it.second.second.first > 3) continue;
        int hei = it.second.first.first;
        if (hei < it.second.second.first) hei = it.second.second.first;
        vecPayes.push_back (std::make_pair(hei, it.first.second));
    }
    std::sort (vecPayes.begin(), vecPayes.end(),
        [&](std::pair<int, CKeyID>& a, std::pair<int, CKeyID>& b) { return a.first > b.first; });
    int ind = (block_height - chei) % vecPayes.size();
    return vecPayes[ind].second;
}

void CVotes::enum_nodes (CNodeInfo enumfunc) {
    LOCK (cs);
    for (const auto& it : cacheNodes)
        enumfunc (it.first, it.second.first, it.second.second);
}     

void CVotes::dump (const std::string& border, std::function<void(std::string)> dumpfunc) {
    {
        LOCK(cs);
        dumpfunc(border + "mapVotes {");
        for (auto& item : mapVotes)
            item.second.dump (border + "        ", dumpfunc);
        dumpfunc(border + "}");
        dumpfunc(border + "mapUnchecked {");
        for (auto& item : mapUnchecked)
            item.second.dump (border + "        ", dumpfunc);
        dumpfunc(border + "}");
        dumpfunc(border + "cacheVoting {");
        for (auto& item : cacheVoting) {
            dumpfunc(border + "    " + itostr(item.first.first) + " (" + item.first.second.ToString() + ") {");
            for (auto& item2 : item.second)
                dumpfunc(border + "        " + item2.first.ToString() + " (" + EncodeDestination(item2.second) + ")");
            dumpfunc(border + "    " + "}");
        }
        dumpfunc(border + "}");
        dumpfunc(border + "cacheNodes {");
        for (auto& item : cacheNodes)
            dumpfunc(border + "    " + item.first.first.ToString() + " (" + EncodeDestination(item.first.second) + ") = " +
                itostr(item.second.first.first) + " (" + item.second.first.second.ToString() + "), " +
                itostr(item.second.second.first) + " (" + item.second.second.second.ToString() + ")");
        dumpfunc(border + "}");
        dumpfunc(border + "cacheVerify {");
        for (auto& item : cacheVerify) {
            dumpfunc(border + "    " + item.first.first.ToString() + " (" + EncodeDestination(item.first.second) + ") {");
            for (auto& item2 : item.second)
                dumpfunc(border + "        " + item2.first.first.ToString() + " (" + EncodeDestination(item2.first.second) + ") = " +
                    itostr(item2.second.first) + " (" + item2.second.second.ToString() + ")");
            dumpfunc(border + "    " + "}");
        }
        dumpfunc(border + "}");
    }
    {
        LOCK (cs_pay);
        dumpfunc(border + "mapPayouts {");
        for (auto& item : mapPayouts)
            dumpfunc(border + "    " + itostr(item.first.first) + " (" + item.first.second.ToString() + ") = " + EncodeDestination(item.second));
        dumpfunc(border + "}");
    }
}

CVotes votes;
