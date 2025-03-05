// Copyright (c) 2014-2019 The Dash Core developers
// Copyright (c) 2021-2025 Uladzimir (t.me/vovanchik_net)
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <clientversion.h>
#include <init.h>
#include <netbase.h>
#include <validation.h>
#include <util.h>
#include <utilmoneystr.h>
#include <txmempool.h>
#include <key_io.h>

#include <masternode.h>

#include <rpc/server.h>

#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif // ENABLE_WALLET

#include <fstream>
#include <iomanip>
#include <univalue.h>

UniValue masternode_count (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_count\n"
            "\nGet count of masternode\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_count", "")
        );

    int total = mnodeman.size();
    int enabled = mnodeman.CountEnabled();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("total", total);
    obj.pushKV("enabled", enabled);
    return obj;
}

UniValue masternode_list (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_list\n"
            "\nDump list of masternodes\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_list", "")
        );

    UniValue obj(UniValue::VOBJ);
    std::map<COutPoint, CMasternode> mapMasternodes = mnodeman.GetFullMasternodeMap();
    for (const auto& mnpair : mapMasternodes) {
        const CMasternode& mn = mnpair.second;
        UniValue objMN(UniValue::VOBJ);
        objMN.pushKV("address", mn.addr.ToString());
        objMN.pushKV("payee", EncodeDestination(mn.pubKeyCollateralAddress.GetID()));
        objMN.pushKV("status", mn.GetStatus());
        objMN.pushKV("protocol", mn.nProtocolVersion);
        objMN.pushKV("lastseen", (int64_t)mn.lastPing.sigTime);
        objMN.pushKV("activeseconds", (int64_t)(mn.lastPing.sigTime - mn.sigTime));
        objMN.pushKV("lastpaidtime", mn.GetLastPaidTime());
        objMN.pushKV("lastpaidblock", mn.GetLastPaidBlock());
        obj.pushKV(mnpair.first.ToString(), objMN);
    }
    return obj;
}

UniValue masternode_outputs (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_outputs\n"
            "\nShow outputs, which masternode can start\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_outputs", "")
        );

    if (GetWallets().size() == 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallets not found");
        
    std::shared_ptr<CWallet> pwallet = GetWallets()[0];
    if (!pwallet)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallets not found");

    std::vector<COutput> vPossibleCoins;
    pwallet->AvailableCoins(vPossibleCoins, true, nullptr, 0, MAX_MONEY, MAX_MONEY, 0, 1, 9999999);
    UniValue obj(UniValue::VOBJ);
    for (const auto& out : vPossibleCoins) {
        if (out.tx->tx->vout[out.i].nValue != Params().GetConsensus().nMasternodeAmountLock * COIN) continue;
        obj.pushKV (out.tx->GetHash().ToString(), strprintf("%d", out.i));
    }
    return obj;
}

UniValue masternode_genkey (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_genkey\n"
            "\nGenerate key for payment\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_genkey", "")
        );

    CKey secret;
    secret.MakeNewKey(false);
    return EncodeSecret(secret);
}

UniValue masternode_config (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_config\n"
            "\nShow masternode config\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_config", "")
        );

    UniValue resultObj(UniValue::VOBJ);
    for (const auto& mne : masternodeConfig.getEntries()) {
        COutPoint outpoint = COutPoint(uint256S(mne.getTxHash()), (uint32_t)atoi(mne.getOutputIndex()));
        CMasternode mn;
        bool fFound = mnodeman.Get(outpoint, mn);

        std::string strStatus = fFound ? mn.GetStatus() : "MISSING";

        UniValue mnObj(UniValue::VOBJ);
        mnObj.pushKV("alias", mne.getAlias());
        mnObj.pushKV("address", mne.getIp());
        mnObj.pushKV("privateKey", mne.getPrivKey());
        mnObj.pushKV("txHash", mne.getTxHash());
        mnObj.pushKV("outputIndex", mne.getOutputIndex());
        mnObj.pushKV("status", strStatus);
        resultObj.pushKV("masternode", mnObj);
    }
    return resultObj;
}

UniValue masternode_create (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_create\n"
            "\nCreate masternode\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_create", "")
        );

    if (GetWallets().size() == 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallets not found");

    std::shared_ptr<CWallet> pwallet = GetWallets()[0];
    if (!pwallet)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallets not found");

    int nn = 0;
    std::vector<COutput> vPossibleCoins;
    pwallet->AvailableCoins(vPossibleCoins, true, nullptr, 0, MAX_MONEY, MAX_MONEY, 0, 1, 9999999);
    UniValue obj(UniValue::VOBJ);
    for (const auto& out : vPossibleCoins) {
        if (out.tx->tx->vout[out.i].nValue != Params().GetConsensus().nMasternodeAmountLock * COIN) continue;
        bool found = false;
        for (const auto& mne : masternodeConfig.getEntries()) {
            if ((out.tx->GetHash().ToString() == mne.getTxHash()) && 
                (mne.getOutputIndex() == itostr(out.i))) { found = true; break; }
        }
        if (!found) {
            CKey secret;
            secret.MakeNewKey(false);
            CService serv;
            bool fFoundLocal = GetLocal(serv) && CMasternode::IsValidNetAddr(serv);
            if (!fFoundLocal) {
                bool empty = true;
                g_connman->ForEachNode([&](CNode* pnode) {
                    empty = false;
                    if (pnode->addr.IsIPv4())
                        fFoundLocal = GetLocal(serv, &pnode->addr) && CMasternode::IsValidNetAddr(serv);
                    return !fFoundLocal;
                });
            }
            if (!serv.IsIPv4()) Lookup("127.0.0.1", serv, 9987, false);
            masternodeConfig.add ("mn"+itostr(masternodeConfig.getCount()+1), serv.ToString(), EncodeSecret(secret), 
                        out.tx->GetHash().ToString(), itostr(out.i));
            obj.pushKV("Added", strprintf("%s:%d", out.tx->GetHash().ToString(), out.i));
            nn++;
        } else {
            obj.pushKV("Existed", strprintf("%s:%d", out.tx->GetHash().ToString(), out.i));
        }
    }
    if (nn > 0) {
        std::string strErrRet;
        masternodeConfig.write(strErrRet);
    }
    return obj; 
}

UniValue masternode_status (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_status\n"
            "\nShow status of current masternode\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_status", "")
        );

    if ((request.params.size() == 1) && (request.params[0].get_str() == "up")) {
        masternodeSync.SwitchToNextAsset(*g_connman);
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("syncstatus", masternodeSync.GetSyncStatus());
        return obj;
    }

    if (!fMasternodeMode)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not a masternode");

    UniValue mnObj(UniValue::VOBJ);

    mnObj.pushKV("outpoint", activeMasternode.outpoint.ToString());
    mnObj.pushKV("service", activeMasternode.service.ToString());

    CMasternode mn;
    if (mnodeman.Get(activeMasternode.outpoint, mn)) {
        mnObj.pushKV("payee", EncodeDestination(mn.pubKeyCollateralAddress.GetID()));
    }

    mnObj.pushKV("status", activeMasternode.GetStatus());
    return mnObj;
}

UniValue masternode_connect (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_connect\n"
            "\nConnect to masternode by address\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_connect", "")
        );

    if (request.params.size() != 1)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Masternode address required");

    std::string strAddress = request.params[0].get_str();

    CService addr;
    if (!Lookup(strAddress.c_str(), addr, 0, false))
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Incorrect masternode address %s", strAddress));

    g_connman->OpenMasternodeConnection(CAddress(addr, NODE_NETWORK));
    bool ret = false;
    g_connman->ForEachNode([&ret, &addr](CNode* pnode) {
        if ((CService)pnode->addr == addr) {
            if (pnode->fMasternode) ret = true;
        }
    });
    if (!ret)
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Couldn't connect to masternode %s", strAddress));

    return "successfully connected";
}

UniValue masternode_current (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_current\n"
            "\nCurrent masternode for payment\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_current", "")
        );

    int nCount;
    int nHeight;
    CMasternodeBase mnInfo;
    if (!mnodeman.GetNextMasternodeInQueueForPayment(nHeight, true, nCount, mnInfo))
        return "unknown";

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("height",        nHeight);
    obj.pushKV("IP:port",       mnInfo.addr.ToString());
    obj.pushKV("protocol",      mnInfo.nProtocolVersion);
    obj.pushKV("outpoint",      mnInfo.outpoint.ToString());
    obj.pushKV("payee",         EncodeDestination(mnInfo.pubKeyCollateralAddress.GetID()));
    obj.pushKV("lastseen",      mnInfo.nTimeLastPing);
    obj.pushKV("activeseconds", mnInfo.nTimeLastPing - mnInfo.sigTime);
    return obj; 
}

UniValue masternode_winners (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_winners\n"
            "\nShow paymentment\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_winners", "")
        );

    int nHeight;
    {
        LOCK(cs_main);
        CBlockIndex* pindex = chainActive.Tip();
        if (!pindex) return NullUniValue;
        nHeight = pindex->nHeight;
    }

    int nLast = 10;
    if (request.params.size() >= 1) {
        nLast = atoi(request.params[0].get_str());
    }
    if (nLast < 10) nLast = 10;
    if (nLast > 5000) nLast = 5000;

    UniValue obj(UniValue::VOBJ);
    for(int i = nHeight - nLast; i < nHeight + 20; i++) {
        std::string strPayment = mnpayments.GetRequiredPaymentsString(i);
        if (i == nHeight) {
            obj.pushKV(strprintf("%d *", i), strPayment);
        } else {
            obj.pushKV(strprintf("%d", i), strPayment);
        }
    }
    return obj;
}

void debug_log (const std::string str) {
    static FILE *cfile_ptr = NULL;
    static int cfile_numinfile = 0;
    static int cfile_count = 0;
    static std::string eol = "\n";
	if (str == "*") { if (cfile_ptr != NULL) fclose(cfile_ptr); cfile_ptr = NULL; return; }
	if ((cfile_ptr != NULL) && (cfile_numinfile > 99999)) { fclose(cfile_ptr); cfile_ptr = NULL; }
	if (cfile_ptr == NULL) { 
		cfile_ptr = fsbridge::fopen(strprintf("debug%06i", ++cfile_count) + ".log", "a");
		cfile_numinfile = 0;
	}
    fwrite(str.data(), 1, str.size(), cfile_ptr);
    fwrite(eol.data(), 1, eol.size(), cfile_ptr);
	cfile_numinfile++;
}

UniValue masternode_dump (const JSONRPCRequest& request) {
    if (request.fHelp)
        throw std::runtime_error(
            "masternode_dump\n"
            "\nDump info about masternodes\n"
            "\nExamples:\n"
            + HelpExampleCli("masternode_dump", "")
        );

    mnodeman.Dump("", [](std::string ss) { debug_log (ss); });
    debug_log ("");
    debug_log ("");
    debug_log ("");
    mnpayments.Dump("", [](std::string ss) { debug_log (ss); });
    debug_log ("");
    debug_log ("");
    debug_log ("");
    votes.dump("", [](std::string ss) { debug_log (ss); });
    debug_log ("*");

    return {};
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "mn",                 "masternode_count",       &masternode_count,       {} },
    { "mn",                 "masternode_list",        &masternode_list,        {} },
    { "mn",                 "masternode_outputs",     &masternode_outputs,     {} },
    { "mn",                 "masternode_genkey",      &masternode_genkey,      {} },
    { "mn",                 "masternode_config",      &masternode_config,      {} },
    { "mn",                 "masternode_create",      &masternode_create,      {} },
    { "mn",                 "masternode_status",      &masternode_status,      {} },
    { "mn",                 "masternode_connect",     &masternode_connect,     {} },
    { "mn",                 "masternode_current",     &masternode_current,     {} },
    { "mn",                 "masternode_winners",     &masternode_winners,     {} },
    { "hidden",             "masternode_dump",        &masternode_dump,        {} },
};

void RegisterMasternodeRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
