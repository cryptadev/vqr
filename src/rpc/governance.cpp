// Copyright (c) 2014-2020 The Dash Core developers
// Copyright (c) 2023 Uladzimir (t.me/cryptadev)
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <core_io.h>
#include <key_io.h>
#include <governance.h>
#include <init.h>
#include <txmempool.h>
#include <validation.h>
#include <masternode.h>
#include <rpc/server.h>
#include <util.h>
#include <utilmoneystr.h>
#include <wallet/rpcwallet.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#include <wallet/coincontrol.h>
#endif // ENABLE_WALLET

int32_t ParseInt32V(const UniValue& v, const std::string &strName)
{
    std::string strNum = v.getValStr();
    int32_t num;
    if (!ParseInt32(strNum, &num))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be a 32bit integer (not '"+strNum+"')");
    return num;
}

int64_t ParseInt64V(const UniValue& v, const std::string &strName)
{
    std::string strNum = v.getValStr();
    int64_t num;
    if (!ParseInt64(strNum, &num))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be a 64bit integer (not '"+strNum+"')");
    return num;
}

UniValue gobject(const JSONRPCRequest& request) {
    std::string strCommand;
    if (request.params.size() >= 1)
        strCommand = request.params[0].get_str();

    if (request.fHelp  ||
        (
#ifdef ENABLE_WALLET
         strCommand != "prepare" &&
#endif // ENABLE_WALLET
         strCommand != "vote-many" && strCommand != "vote-conf" && strCommand != "vote-alias" && strCommand != "submit" && strCommand != "count" &&
         strCommand != "deserialize" && strCommand != "get" && strCommand != "getvotes" && strCommand != "getcurrentvotes" && strCommand != "list" && strCommand != "diff" &&
         strCommand != "check" ))
        throw std::runtime_error(
                "gobject \"command\"...\n"
                "Manage governance objects\n"
                "\nAvailable commands:\n"
                "  check              - Validate governance object data (proposal only)\n"
#ifdef ENABLE_WALLET
                "  prepare            - Prepare governance object by signing and creating tx\n"
#endif // ENABLE_WALLET
                "  submit             - Submit governance object to network\n"
                "  deserialize        - Deserialize governance object from hex string to JSON\n"
                "  count              - Count governance objects and votes (additional param: 'json' or 'all', default: 'json')\n"
                "  get                - Get governance object by hash\n"
                "  getvotes           - Get all votes for a governance object hash (including old votes)\n"
                "  getcurrentvotes    - Get only current (tallying) votes for a governance object hash (does not include old votes)\n"
                "  list               - List governance objects (can be filtered by signal and/or object type)\n"
                "  diff               - List differences since last diff\n"
                "  vote-alias         - Vote on a governance object by masternode alias (using masternode.conf setup)\n"
                "  vote-conf          - Vote on a governance object by masternode configured in dash.conf\n"
                "  vote-many          - Vote on a governance object by all masternodes (using masternode.conf setup)\n"
                );


    if(strCommand == "count") {
        std::string strMode{"json"};

        if (request.params.size() == 2) {
            strMode = request.params[1].get_str();
        }

        if (request.params.size() > 2 || (strMode != "json" && strMode != "all")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'gobject count ( \"json\"|\"all\" )'");
        }

        return strMode == "json" ? governance.ToJson() : governance.ToString();
    }

    // DEBUG : TEST DESERIALIZATION OF GOVERNANCE META DATA
    if(strCommand == "deserialize")
    {
        if (request.params.size() != 2) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'gobject deserialize <data-hex>'");
        }

        std::string strHex = request.params[1].get_str();

        std::vector<unsigned char> v = ParseHex(strHex);
        std::string s(v.begin(), v.end());

        UniValue u(UniValue::VOBJ);
        u.read(s);

        return u.write().c_str();
    }

    // VALIDATE A GOVERNANCE OBJECT PRIOR TO SUBMISSION
    if(strCommand == "check")
    {

        // ASSEMBLE NEW GOVERNANCE OBJECT FROM USER PARAMETERS

        uint256 hashParent;

        int nRevision = 1;

        int64_t nTime = GetAdjustedTime();
        std::string strDataHex = request.params[1].get_str();

        CGovernanceObject govobj(hashParent, nRevision, nTime, uint256(), strDataHex);

        if (govobj.GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
            CProposalValidator validator(strDataHex);
            if (!validator.Validate())  {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid proposal data, error messages:" + validator.GetErrorMessages());
            }
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid object type, only proposals can be validated");
        }

        UniValue objResult(UniValue::VOBJ);

        objResult.pushKV("Object status", "OK");

        return objResult;
    }

#ifdef ENABLE_WALLET
    // PREPARE THE GOVERNANCE OBJECT BY CREATING A COLLATERAL TRANSACTION
    if(strCommand == "prepare")
    {
        std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
        CWallet* const pwallet = wallet.get();
        if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
            return NullUniValue;
        }

        if (request.params.size() != 5) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'gobject prepare <parent-hash> <revision> <time> <data-hex>'");
        }

        // ASSEMBLE NEW GOVERNANCE OBJECT FROM USER PARAMETERS

        uint256 hashParent;

        // -- attach to root node (root node doesn't really exist, but has a hash of zero)
        if (request.params[1].get_str() == "0") {
            hashParent = uint256();
        } else {
            hashParent = ParseHashV(request.params[1], "parent-hash");
        }

        int nRevision = ParseInt32V(request.params[2], "revision");
        int64_t nTime = ParseInt64V(request.params[3], "time");
        std::string strDataHex = request.params[4].get_str();

        // CREATE A NEW COLLATERAL TRANSACTION FOR THIS SPECIFIC OBJECT

        CGovernanceObject govobj(hashParent, nRevision, nTime, uint256(), strDataHex);

        if (govobj.GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
            CProposalValidator validator(strDataHex);
            if (!validator.Validate()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid proposal data, error messages:" + validator.GetErrorMessages());
            }
        }

        if (govobj.GetObjectType() == GOVERNANCE_OBJECT_TRIGGER) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Trigger objects need not be prepared (however only masternodes can create them)");
        }

        if (govobj.GetObjectType() == GOVERNANCE_OBJECT_WATCHDOG) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Watchdogs are deprecated");
        }

        LOCK2(cs_main, pwallet->cs_wallet);

        std::string strError = "";
        if (!govobj.IsValidLocally(strError, false))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Governance object is not valid - " + govobj.GetHash().ToString() + " - " + strError);

        CTransactionRef tx;
        CReserveKey reservekey2(pwallet);
        CScript scriptChange;
        scriptChange << OP_RETURN << ToByteVector(govobj.GetHash()); 

        CAmount nFeeRet = 0;
        int nChangePosRet = -1;
        std::string strFail = "";
        std::vector <CRecipient> vecSend;
        vecSend.push_back((CRecipient){scriptChange, govobj.GetMinCollateralFee(), false});
        CCoinControl coinControl;
        
        bool success = pwallet->CreateTransaction (vecSend, tx, reservekey2, nFeeRet, nChangePosRet, strFail, coinControl);
        if (!success) {
            std::string err = "Error making collateral transaction for governance object. Please check your wallet balance and make sure your wallet is unlocked.";
            throw JSONRPCError(RPC_INTERNAL_ERROR, err);
        }
 

        // -- make our change address
        CReserveKey reservekey(pwallet);
        // -- send the tx to the network
        CValidationState state;
        if (!pwallet->CommitTransaction(tx, {}, {}, {}, reservekey, g_connman.get(), state)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "CommitTransaction failed! Reason given: " + state.GetRejectReason());
        }

        LogPrint(BCLog::MN, "gobject_prepare -- GetDataAsPlainString = %s, hash = %s, txid = %s\n",
                    govobj.GetDataAsPlainString(), govobj.GetHash().ToString(), tx->GetHash().ToString());

        return tx->GetHash().ToString();
    }
#endif // ENABLE_WALLET

    if(strCommand == "submit")
    {
        if ((request.params.size() < 5) || (request.params.size() > 6))  {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'gobject submit <parent-hash> <revision> <time> <data-hex> <fee-txid>'");
        }

        if (!masternodeSync.IsBlockchainSynced()) {
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Must wait for client to sync with masternode network. Try again in a minute or so.");
        }

        bool fMnFound = mnodeman.Has(activeMasternode.outpoint);

        LogPrint(BCLog::MN, "gobject_submit -- pubKeyOperator = %s, outpoint = %s, params.size() = %lld, fMnFound = %d\n",
                activeMasternode.pubKeyMasternode.GetHash().ToString(),
                activeMasternode.outpoint.ToString(), request.params.size(), fMnFound);

        // ASSEMBLE NEW GOVERNANCE OBJECT FROM USER PARAMETERS

        uint256 txidFee;

        if (!request.params[5].isNull()) {
            txidFee = ParseHashV(request.params[5], "fee-txid");
        }
        uint256 hashParent;
        if (request.params[1].get_str() == "0") { // attach to root node (root node doesn't really exist, but has a hash of zero)
            hashParent = uint256();
        } else {
            hashParent = ParseHashV(request.params[1], "parent-hash");
        }

        // GET THE PARAMETERS FROM USER

        int nRevision = ParseInt32V(request.params[2], "revision");
        int64_t nTime = ParseInt64V(request.params[3], "time");
        std::string strDataHex = request.params[4].get_str();

        CGovernanceObject govobj(hashParent, nRevision, nTime, txidFee, strDataHex);

        LogPrint(BCLog::MN, "gobject_submit -- GetDataAsPlainString = %s, hash = %s, txid = %s\n",
                    govobj.GetDataAsPlainString(), govobj.GetHash().ToString(), txidFee.ToString());

        if (govobj.GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
            CProposalValidator validator(strDataHex);
            if (!validator.Validate()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid proposal data, error messages:" + validator.GetErrorMessages());
            }
        }

        if(govobj.GetObjectType() == GOVERNANCE_OBJECT_WATCHDOG) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Watchdogs are deprecated");
        }

        // Attempt to sign triggers if we are a MN
        if (govobj.GetObjectType() == GOVERNANCE_OBJECT_TRIGGER) {
            if (fMnFound) {
                govobj.SetMasternodeOutpoint(activeMasternode.outpoint);
                govobj.Sign(activeMasternode.keyMasternode, activeMasternode.pubKeyMasternode);
            } else {
                LogPrintf("gobject(submit) -- Object submission rejected because node is not a masternode\n");
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only valid masternodes can submit this type of object");
            }
        } else if (request.params.size() != 6) {
            LogPrintf("gobject(submit) -- Object submission rejected because fee tx not provided\n");
            throw JSONRPCError(RPC_INVALID_PARAMETER, "The fee-txid parameter must be included to submit this type of object");
        }

        std::string strHash = govobj.GetHash().ToString();

        std::string strError = "";
        bool fMissingMasternode;
        bool fMissingConfirmations;
        {
            LOCK(cs_main);
            if(!govobj.IsValidLocally(strError, fMissingMasternode, fMissingConfirmations, true) && !fMissingConfirmations) {
                LogPrintf("gobject(submit) -- Object submission rejected because object is not valid - hash = %s, strError = %s\n", strHash, strError);
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Governance object is not valid - " + strHash + " - " + strError);
            }
        }

        // RELAY THIS OBJECT
        // Reject if rate check fails but don't update buffer
        if (!governance.MasternodeRateCheck(govobj)) {
            LogPrintf("gobject(submit) -- Object submission rejected because of rate check failure - hash = %s\n", strHash);
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Object creation rate limit exceeded");
        }

        LogPrintf("gobject(submit) -- Adding locally created governance object - %s\n", strHash);

        if (fMissingConfirmations) {
            governance.AddPostponedObject(govobj);
            govobj.Relay(*g_connman);
        } else {
            governance.AddGovernanceObject(govobj, *g_connman);
        }

        return govobj.GetHash().ToString();
    }

    if(strCommand == "vote-conf")
    {
        if(request.params.size() != 4)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'gobject vote-conf <governance-hash> [funding|valid|delete] [yes|no|abstain]'");

        uint256 hash;

        hash = ParseHashV(request.params[1], "Object hash");
        std::string strVoteSignal = request.params[2].get_str();
        std::string strVoteOutcome = request.params[3].get_str();

        vote_signal_enum_t eVoteSignal = CGovernanceVoting::ConvertVoteSignal(strVoteSignal);
        if (eVoteSignal == VOTE_SIGNAL_NONE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, 
                "Invalid vote signal. Please using one of the following: (funding|valid|delete|endorsed)");
        }

        vote_outcome_enum_t eVoteOutcome = CGovernanceVoting::ConvertVoteOutcome(strVoteOutcome);
        if (eVoteOutcome == VOTE_OUTCOME_NONE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid vote outcome. Please use one of the following: 'yes', 'no' or 'abstain'");
        }

        int nSuccessful = 0;
        int nFailed = 0;

        UniValue resultsObj(UniValue::VOBJ);

        std::vector<unsigned char> vchMasterNodeSignature;
        std::string strMasterNodeSignMessage;

        UniValue statusObj(UniValue::VOBJ);
        UniValue returnObj(UniValue::VOBJ);

        CMasternode mn;
        bool fMnFound = mnodeman.Get(activeMasternode.outpoint, mn);

        if (!fMnFound) {
            nFailed++;
            statusObj.pushKV("result", "failed");
            statusObj.pushKV("errorMessage", "Can't find masternode by collateral output");
            resultsObj.pushKV("vqr.conf", statusObj);
            returnObj.pushKV("overall", strprintf("Voted successfully %d time(s) and failed %d time(s).", nSuccessful, nFailed));
            returnObj.pushKV("detail", resultsObj);
            return returnObj;
        }

        CGovernanceVote vote(mn.outpoint, hash, eVoteSignal, eVoteOutcome);
        if(!vote.Sign(activeMasternode.keyMasternode, activeMasternode.pubKeyMasternode)) {
            nFailed++;
            statusObj.pushKV("result", "failed");
            statusObj.pushKV("errorMessage", "Failure to sign.");
            resultsObj.pushKV("dash.conf", statusObj);
            returnObj.pushKV("overall", strprintf("Voted successfully %d time(s) and failed %d time(s).", nSuccessful, nFailed));
            returnObj.pushKV("detail", resultsObj);
            return returnObj;
        }

        CGovernanceException exception;
        if (governance.ProcessVoteAndRelay(vote, exception, *g_connman)) {
            nSuccessful++;
            statusObj.pushKV("result", "success");
        } else {
            nFailed++;
            statusObj.pushKV("result", "failed");
            statusObj.pushKV("errorMessage", exception.GetMessage());
        }

        resultsObj.pushKV("vqr.conf", statusObj);

        returnObj.pushKV("overall", strprintf("Voted successfully %d time(s) and failed %d time(s).", nSuccessful, nFailed));
        returnObj.pushKV("detail", resultsObj);

        return returnObj;
    }
    
    if(strCommand == "vote-many")
    {
        if(request.params.size() != 4)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'gobject vote-many <governance-hash> [funding|valid|delete] [yes|no|abstain]'");

        std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
        CWallet* const pwallet = wallet.get();
        if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) return NullUniValue;

        uint256 hash;
        std::string strVote;

        hash = ParseHashV(request.params[1], "Object hash");
        std::string strVoteSignal = request.params[2].get_str();
        std::string strVoteOutcome = request.params[3].get_str();

        vote_signal_enum_t eVoteSignal = CGovernanceVoting::ConvertVoteSignal(strVoteSignal);
        if (eVoteSignal == VOTE_SIGNAL_NONE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Invalid vote signal. Please using one of the following: (funding|valid|delete|endorsed)");
        }

        vote_outcome_enum_t eVoteOutcome = CGovernanceVoting::ConvertVoteOutcome(strVoteOutcome);
        if (eVoteOutcome == VOTE_OUTCOME_NONE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid vote outcome. Please use one of the following: 'yes', 'no' or 'abstain'");
        }

        EnsureWalletIsUnlocked(pwallet);

        int nSuccessful = 0;
        int nFailed = 0;

        UniValue resultsObj(UniValue::VOBJ);

        for (const auto& mne : masternodeConfig.getEntries()) {
            std::string strError;
            std::vector<unsigned char> vchMasterNodeSignature;
            std::string strMasterNodeSignMessage;

            CPubKey pubKeyCollateralAddress;
            CKey keyCollateralAddress;
            CPubKey pubKeyMasternode;
            CKey keyMasternode;

            UniValue statusObj(UniValue::VOBJ);

            if(!CMessageSigner::GetKeysFromSecret(mne.getPrivKey(), keyMasternode, pubKeyMasternode)){
                nFailed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Masternode signing error, could not set key correctly"));
                resultsObj.push_back(Pair(mne.getAlias(), statusObj));
                continue;
            }

            uint256 nTxHash;
            nTxHash.SetHex(mne.getTxHash());

            int nOutputIndex = 0;
            if(!ParseInt32(mne.getOutputIndex(), &nOutputIndex)) {
                continue;
            }

            COutPoint outpoint(nTxHash, nOutputIndex);

            CMasternode mn;
            bool fMnFound = mnodeman.Get(outpoint, mn);

            if(!fMnFound) {
                nFailed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Can't find masternode by collateral output"));
                resultsObj.push_back(Pair(mne.getAlias(), statusObj));
                continue;
            }

            CGovernanceVote vote(mn.outpoint, hash, eVoteSignal, eVoteOutcome);
            if(!vote.Sign(keyMasternode, pubKeyMasternode)){
                nFailed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Failure to sign."));
                resultsObj.push_back(Pair(mne.getAlias(), statusObj));
                continue;
            }

            CGovernanceException exception;
            if(governance.ProcessVoteAndRelay(vote, exception, *g_connman)) {
                nSuccessful++;
                statusObj.push_back(Pair("result", "success"));
            }
            else {
                nFailed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", exception.GetMessage()));
            }

            resultsObj.push_back(Pair(mne.getAlias(), statusObj));
        }

        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Voted successfully %d time(s) and failed %d time(s).", nSuccessful, nFailed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }

    // MASTERNODES CAN VOTE ON GOVERNANCE OBJECTS ON THE NETWORK FOR VARIOUS SIGNALS AND OUTCOMES
    if(strCommand == "vote-alias")
    {
        if(request.params.size() != 5)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'gobject vote-alias <governance-hash> [funding|valid|delete] [yes|no|abstain] <alias-name>'");

        uint256 hash;
        std::string strVote;

        // COLLECT NEEDED PARAMETRS FROM USER

        hash = ParseHashV(request.params[1], "Object hash");
        std::string strVoteSignal = request.params[2].get_str();
        std::string strVoteOutcome = request.params[3].get_str();
        std::string strAlias = request.params[4].get_str();

        // CONVERT NAMED SIGNAL/ACTION AND CONVERT

        vote_signal_enum_t eVoteSignal = CGovernanceVoting::ConvertVoteSignal(strVoteSignal);
        if(eVoteSignal == VOTE_SIGNAL_NONE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid vote signal. Please using one of the following: "
                               "(funding|valid|delete|endorsed)");
        }

        vote_outcome_enum_t eVoteOutcome = CGovernanceVoting::ConvertVoteOutcome(strVoteOutcome);
        if(eVoteOutcome == VOTE_OUTCOME_NONE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid vote outcome. Please use one of the following: 'yes', 'no' or 'abstain'");
        }

        // EXECUTE VOTE FOR EACH MASTERNODE, COUNT SUCCESSES VS FAILURES

        int nSuccessful = 0;
        int nFailed = 0;

        UniValue resultsObj(UniValue::VOBJ);

        for (const auto& mne : masternodeConfig.getEntries())
        {
            // IF WE HAVE A SPECIFIC NODE REQUESTED TO VOTE, DO THAT
            if(strAlias != mne.getAlias()) continue;

            // INIT OUR NEEDED VARIABLES TO EXECUTE THE VOTE
            std::string strError;
            std::vector<unsigned char> vchMasterNodeSignature;
            std::string strMasterNodeSignMessage;

            CPubKey pubKeyCollateralAddress;
            CKey keyCollateralAddress;
            CPubKey pubKeyMasternode;
            CKey keyMasternode;

            // SETUP THE SIGNING KEY FROM MASTERNODE.CONF ENTRY

            UniValue statusObj(UniValue::VOBJ);

            if(!CMessageSigner::GetKeysFromSecret(mne.getPrivKey(), keyMasternode, pubKeyMasternode)) {
                nFailed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", strprintf("Invalid masternode key %s.", mne.getPrivKey())));
                resultsObj.push_back(Pair(mne.getAlias(), statusObj));
                continue;
            }

            // SEARCH FOR THIS MASTERNODE ON THE NETWORK, THE NODE MUST BE ACTIVE TO VOTE

            uint256 nTxHash;
            nTxHash.SetHex(mne.getTxHash());

            int nOutputIndex = 0;
            if(!ParseInt32(mne.getOutputIndex(), &nOutputIndex)) {
                continue;
            }

            COutPoint outpoint(nTxHash, nOutputIndex);

            CMasternode mn;
            bool fMnFound = mnodeman.Get(outpoint, mn);

            if(!fMnFound) {
                nFailed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Masternode must be publicly available on network to vote. Masternode not found."));
                resultsObj.push_back(Pair(mne.getAlias(), statusObj));
                continue;
            }

            // CREATE NEW GOVERNANCE OBJECT VOTE WITH OUTCOME/SIGNAL

            CGovernanceVote vote(outpoint, hash, eVoteSignal, eVoteOutcome);
            if(!vote.Sign(keyMasternode, pubKeyMasternode)) {
                nFailed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", "Failure to sign."));
                resultsObj.push_back(Pair(mne.getAlias(), statusObj));
                continue;
            }

            // UPDATE LOCAL DATABASE WITH NEW OBJECT SETTINGS

            CGovernanceException exception;
            if(governance.ProcessVoteAndRelay(vote, exception, *g_connman)) {
                nSuccessful++;
                statusObj.push_back(Pair("result", "success"));
            }
            else {
                nFailed++;
                statusObj.push_back(Pair("result", "failed"));
                statusObj.push_back(Pair("errorMessage", exception.GetMessage()));
            }

            resultsObj.push_back(Pair(mne.getAlias(), statusObj));
        }

        // REPORT STATS TO THE USER

        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Voted successfully %d time(s) and failed %d time(s).", nSuccessful, nFailed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }

    // USERS CAN QUERY THE SYSTEM FOR A LIST OF VARIOUS GOVERNANCE ITEMS
    if(strCommand == "list" || strCommand == "diff")
    {
        if (request.params.size() > 3)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'gobject [list|diff] ( signal type )'");

        // GET MAIN PARAMETER FOR THIS MODE, VALID OR ALL?

        std::string strCachedSignal = "valid";
        if (request.params.size() >= 2) strCachedSignal = request.params[1].get_str();
        if (strCachedSignal != "valid" && strCachedSignal != "funding" && strCachedSignal != "delete" && strCachedSignal != "endorsed" && strCachedSignal != "all")
            return "Invalid signal, should be 'valid', 'funding', 'delete', 'endorsed' or 'all'";

        std::string strType = "all";
        if (request.params.size() == 3) strType = request.params[2].get_str();
        if (strType != "proposals" && strType != "triggers" && strType != "all")
            return "Invalid type, should be 'proposals', 'triggers' or 'all'";

        // GET STARTING TIME TO QUERY SYSTEM WITH

        int nStartTime = 0; //list
        if(strCommand == "diff") nStartTime = governance.GetLastDiffTime();

        // SETUP BLOCK INDEX VARIABLE / RESULTS VARIABLE

        UniValue objResult(UniValue::VOBJ);

        // GET MATCHING GOVERNANCE OBJECTS

        LOCK2(cs_main, governance.cs);

        std::vector<const CGovernanceObject*> objs = governance.GetAllNewerThan(nStartTime);
        governance.UpdateLastDiffTime(GetTime());

        // CREATE RESULTS FOR USER

        for (const auto& pGovObj : objs)
        {
            if(strCachedSignal == "valid" && !pGovObj->IsSetCachedValid()) continue;
            if(strCachedSignal == "funding" && !pGovObj->IsSetCachedFunding()) continue;
            if(strCachedSignal == "delete" && !pGovObj->IsSetCachedDelete()) continue;
            if(strCachedSignal == "endorsed" && !pGovObj->IsSetCachedEndorsed()) continue;

            if(strType == "proposals" && pGovObj->GetObjectType() != GOVERNANCE_OBJECT_PROPOSAL) continue;
            if(strType == "triggers" && pGovObj->GetObjectType() != GOVERNANCE_OBJECT_TRIGGER) continue;

            UniValue bObj(UniValue::VOBJ);
            bObj.push_back(Pair("DataHex",  pGovObj->GetDataAsHexString()));
            bObj.push_back(Pair("DataString",  pGovObj->GetDataAsPlainString()));
            bObj.push_back(Pair("Hash",  pGovObj->GetHash().ToString()));
            bObj.push_back(Pair("CollateralHash",  pGovObj->GetCollateralHash().ToString()));
            bObj.push_back(Pair("ObjectType", pGovObj->GetObjectType()));
            bObj.push_back(Pair("CreationTime", pGovObj->GetCreationTime()));
            const COutPoint& masternodeOutpoint = pGovObj->GetMasternodeOutpoint();
            if(masternodeOutpoint != COutPoint()) {
                bObj.push_back(Pair("SigningMasternode", masternodeOutpoint.ToString()));
            }

            // REPORT STATUS FOR FUNDING VOTES SPECIFICALLY
            bObj.push_back(Pair("AbsoluteYesCount",  pGovObj->GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING)));
            bObj.push_back(Pair("YesCount",  pGovObj->GetYesCount(VOTE_SIGNAL_FUNDING)));
            bObj.push_back(Pair("NoCount",  pGovObj->GetNoCount(VOTE_SIGNAL_FUNDING)));
            bObj.push_back(Pair("AbstainCount",  pGovObj->GetAbstainCount(VOTE_SIGNAL_FUNDING)));

            // REPORT VALIDITY AND CACHING FLAGS FOR VARIOUS SETTINGS
            std::string strError = "";
            bObj.push_back(Pair("fBlockchainValidity",  pGovObj->IsValidLocally(strError, false)));
            bObj.push_back(Pair("IsValidReason",  strError.c_str()));
            bObj.push_back(Pair("fCachedValid",  pGovObj->IsSetCachedValid()));
            bObj.push_back(Pair("fCachedFunding",  pGovObj->IsSetCachedFunding()));
            bObj.push_back(Pair("fCachedDelete",  pGovObj->IsSetCachedDelete()));
            bObj.push_back(Pair("fCachedEndorsed",  pGovObj->IsSetCachedEndorsed()));

            objResult.push_back(Pair(pGovObj->GetHash().ToString(), bObj));
        }

        return objResult;
    }

    // GET SPECIFIC GOVERNANCE ENTRY
    if(strCommand == "get")
    {
        if (request.params.size() != 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'gobject get <governance-hash>'");

        // COLLECT VARIABLES FROM OUR USER
        uint256 hash = ParseHashV(request.params[1], "GovObj hash");

        LOCK2(cs_main, governance.cs);

        // FIND THE GOVERNANCE OBJECT THE USER IS LOOKING FOR
        CGovernanceObject* pGovObj = governance.FindGovernanceObject(hash);

        if(pGovObj == nullptr)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown governance object");

        // REPORT BASIC OBJECT STATS

        UniValue objResult(UniValue::VOBJ);
        objResult.push_back(Pair("DataHex",  pGovObj->GetDataAsHexString()));
        objResult.push_back(Pair("DataString",  pGovObj->GetDataAsPlainString()));
        objResult.push_back(Pair("Hash",  pGovObj->GetHash().ToString()));
        objResult.push_back(Pair("CollateralHash",  pGovObj->GetCollateralHash().ToString()));
        objResult.push_back(Pair("ObjectType", pGovObj->GetObjectType()));
        objResult.push_back(Pair("CreationTime", pGovObj->GetCreationTime()));
        const COutPoint& masternodeOutpoint = pGovObj->GetMasternodeOutpoint();
        if(masternodeOutpoint != COutPoint()) {
            objResult.push_back(Pair("SigningMasternode", masternodeOutpoint.ToString()));
        }

        // SHOW (MUCH MORE) INFORMATION ABOUT VOTES FOR GOVERNANCE OBJECT (THAN LIST/DIFF ABOVE)
        // -- FUNDING VOTING RESULTS

        UniValue objFundingResult(UniValue::VOBJ);
        objFundingResult.pushKV("AbsoluteYesCount",  pGovObj->GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING));
        objFundingResult.pushKV("YesCount",  pGovObj->GetYesCount(VOTE_SIGNAL_FUNDING));
        objFundingResult.pushKV("NoCount",  pGovObj->GetNoCount(VOTE_SIGNAL_FUNDING));
        objFundingResult.pushKV("AbstainCount",  pGovObj->GetAbstainCount(VOTE_SIGNAL_FUNDING));
        objResult.pushKV("FundingResult", objFundingResult);

        // -- VALIDITY VOTING RESULTS
        UniValue objValid(UniValue::VOBJ);
        objValid.pushKV("AbsoluteYesCount",  pGovObj->GetAbsoluteYesCount(VOTE_SIGNAL_VALID));
        objValid.pushKV("YesCount",  pGovObj->GetYesCount(VOTE_SIGNAL_VALID));
        objValid.pushKV("NoCount",  pGovObj->GetNoCount(VOTE_SIGNAL_VALID));
        objValid.pushKV("AbstainCount",  pGovObj->GetAbstainCount(VOTE_SIGNAL_VALID));
        objResult.pushKV("ValidResult", objValid);

        // -- DELETION CRITERION VOTING RESULTS
        UniValue objDelete(UniValue::VOBJ);
        objDelete.pushKV("AbsoluteYesCount",  pGovObj->GetAbsoluteYesCount(VOTE_SIGNAL_DELETE));
        objDelete.pushKV("YesCount",  pGovObj->GetYesCount(VOTE_SIGNAL_DELETE));
        objDelete.pushKV("NoCount",  pGovObj->GetNoCount(VOTE_SIGNAL_DELETE));
        objDelete.pushKV("AbstainCount",  pGovObj->GetAbstainCount(VOTE_SIGNAL_DELETE));
        objResult.pushKV("DeleteResult", objDelete);

        // -- ENDORSED VIA MASTERNODE-ELECTED BOARD
        UniValue objEndorsed(UniValue::VOBJ);
        objEndorsed.pushKV("AbsoluteYesCount",  pGovObj->GetAbsoluteYesCount(VOTE_SIGNAL_ENDORSED));
        objEndorsed.pushKV("YesCount",  pGovObj->GetYesCount(VOTE_SIGNAL_ENDORSED));
        objEndorsed.pushKV("NoCount",  pGovObj->GetNoCount(VOTE_SIGNAL_ENDORSED));
        objEndorsed.pushKV("AbstainCount",  pGovObj->GetAbstainCount(VOTE_SIGNAL_ENDORSED));
        objResult.pushKV("EndorsedResult", objEndorsed);

        // --
        std::string strError = "";
        objResult.pushKV("fLocalValidity",  pGovObj->IsValidLocally(strError, false));
        objResult.pushKV("IsValidReason",  strError.c_str());
        objResult.pushKV("fCachedValid",  pGovObj->IsSetCachedValid());
        objResult.pushKV("fCachedFunding",  pGovObj->IsSetCachedFunding());
        objResult.pushKV("fCachedDelete",  pGovObj->IsSetCachedDelete());
        objResult.pushKV("fCachedEndorsed",  pGovObj->IsSetCachedEndorsed());
        return objResult;
    }

    // GETVOTES FOR SPECIFIC GOVERNANCE OBJECT
    if(strCommand == "getvotes")
    {
        if (request.params.size() != 2)
            throw std::runtime_error("Correct usage is 'gobject getvotes <governance-hash>'");

        // COLLECT PARAMETERS FROM USER

        uint256 hash = ParseHashV(request.params[1], "Governance hash");

        // FIND OBJECT USER IS LOOKING FOR

        LOCK(governance.cs);

        CGovernanceObject* pGovObj = governance.FindGovernanceObject(hash);

        if (pGovObj == nullptr) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown governance-hash");
        }

        // REPORT RESULTS TO USER

        UniValue bResult(UniValue::VOBJ);

        // GET MATCHING VOTES BY HASH, THEN SHOW USERS VOTE INFORMATION

        std::vector<CGovernanceVote> vecVotes = governance.GetMatchingVotes(hash);
        for (const auto& vote : vecVotes) {
            bResult.pushKV(vote.GetHash().ToString(),  vote.ToString());
        }

        return bResult;
    }

    // GETVOTES FOR SPECIFIC GOVERNANCE OBJECT
    if (strCommand == "getcurrentvotes")
    {
        if (request.params.size() != 2 && request.params.size() != 4)
            throw std::runtime_error(
                "Correct usage is 'gobject getcurrentvotes <governance-hash> [txid vout_index]'"
                );

        // COLLECT PARAMETERS FROM USER

        uint256 hash = ParseHashV(request.params[1], "Governance hash");

        COutPoint mnCollateralOutpoint;
        if (request.params.size() == 4) {
            uint256 txid = ParseHashV(request.params[2], "Masternode Collateral hash");
            std::string strVout = request.params[3].get_str();
            mnCollateralOutpoint = COutPoint(txid, (uint32_t)atoi(strVout));
        }

        // FIND OBJECT USER IS LOOKING FOR

        LOCK(governance.cs);

        CGovernanceObject* pGovObj = governance.FindGovernanceObject(hash);

        if(pGovObj == nullptr) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown governance-hash");
        }

        // REPORT RESULTS TO USER

        UniValue bResult(UniValue::VOBJ);

        // GET MATCHING VOTES BY HASH, THEN SHOW USERS VOTE INFORMATION

        std::vector<CGovernanceVote> vecVotes = governance.GetCurrentVotes(hash, mnCollateralOutpoint);
        for (const auto& vote : vecVotes) {
            bResult.push_back(Pair(vote.GetHash().ToString(),  vote.ToString()));
        }

        return bResult;
    }

    return NullUniValue;
}

UniValue voteraw(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 7)
        throw std::runtime_error(
                "voteraw <masternode-tx-hash> <masternode-tx-index> <governance-hash> <vote-signal> [yes|no|abstain] <time> <vote-sig>\n"
                "Compile and relay a governance vote with provided external signature instead of signing vote internally\n"
                );

    uint256 hashMnTx = ParseHashV(request.params[0], "mn tx hash");
    int nMnTxIndex = request.params[1].get_int();
    COutPoint outpoint = COutPoint(hashMnTx, nMnTxIndex);

    uint256 hashGovObj = ParseHashV(request.params[2], "Governance hash");
    std::string strVoteSignal = request.params[3].get_str();
    std::string strVoteOutcome = request.params[4].get_str();

    vote_signal_enum_t eVoteSignal = CGovernanceVoting::ConvertVoteSignal(strVoteSignal);
    if (eVoteSignal == VOTE_SIGNAL_NONE)  {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Invalid vote signal. Please using one of the following: "
                           "(funding|valid|delete|endorsed)");
    }

    vote_outcome_enum_t eVoteOutcome = CGovernanceVoting::ConvertVoteOutcome(strVoteOutcome);
    if (eVoteOutcome == VOTE_OUTCOME_NONE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid vote outcome. Please use one of the following: 'yes', 'no' or 'abstain'");
    }

    int64_t nTime = request.params[5].get_int64();
    std::string strSig = request.params[6].get_str();
    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSig.c_str(), &fInvalid);

    if (fInvalid) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");
    }

    CMasternode mn;
    bool fMnFound = mnodeman.Get(outpoint, mn);

    if(!fMnFound) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failure to find masternode in list : " + outpoint.ToString());
    }

    CGovernanceVote vote(outpoint, hashGovObj, eVoteSignal, eVoteOutcome);
    vote.SetTime(nTime);
    vote.SetSignature(vchSig);

    if(!vote.IsValid(true)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failure to verify vote.");
    }

    CGovernanceException exception;
    if (governance.ProcessVoteAndRelay(vote, exception, *g_connman)) {
        return "Voted successfully";
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Error voting : " + exception.GetMessage());
    }
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    /* Dash features */
    { "dash",               "gobject",                &gobject,                {} },
    { "dash",               "voteraw",                &voteraw,                {"tx_hash","tx_index","gov_hash","signal","outcome","time","sig"} },

};

void RegisterGovernanceRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
