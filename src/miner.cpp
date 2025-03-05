// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2021-2025 Uladzimir (t.me/vovanchik_net)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <hash.h>
#include <net.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <timedata.h>
#include <util.h>
#include <utilmoneystr.h>
#include "masternode.h"
#include <validationinterface.h>
#include <key_io.h>
#include <shutdown.h>

#include <algorithm>
#include <queue>
#include <utility>

#include <wallet/wallet.h>

// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest fee rate of a transaction combined with all
// its ancestors.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockWeight = 0;

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
}

BlockAssembler::BlockAssembler(const CChainParams& params, const Options& options) : chainparams(params)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(MAX_BLOCK_WEIGHT - 4000, options.nBlockMaxWeight));
}

static BlockAssembler::Options DefaultOptions()
{
    // Block resource limits
    // If -blockmaxweight is not given, limit to DEFAULT_BLOCK_MAX_WEIGHT
    BlockAssembler::Options options;
    options.nBlockMaxWeight = gArgs.GetArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
    if (gArgs.IsArgSet("-blockmintxfee")) {
        CAmount n = 0;
        ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n);
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CChainParams& params) : BlockAssembler(params, DefaultOptions()) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx)
{
    bool fPosCancel = false;
    return CreateNewBlock(scriptPubKeyIn, fMineWitnessTx, false, fPosCancel, nullptr);
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewPoSBlock(bool& fPoSCancel, std::shared_ptr<CWallet> pwallet, bool fMineWitnessTx)
{
    CScript scriptDummy = CScript() << OP_TRUE;
    return CreateNewBlock(scriptDummy, fMineWitnessTx, true, fPoSCancel, pwallet);
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx, bool fAddProofOfStake, bool& fPoSCancel, std::shared_ptr<CWallet> pwallet)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);
    CBlockIndex* pindexPrev = chainActive.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = 0x20000000;
    pblock->hashPrevBlock = pindexPrev->GetBlockHash();
    pblock->nNonce = fAddProofOfStake ? 0 : 1;
    pblock->nBits = GetNextWorkRequired (pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nTime = std::max(pindexPrev->GetBlockTime()+1, GetAdjustedTime());
 
    CAmount nPosReward;
    if (fAddProofOfStake) {
        CMutableTransaction txNew;
        fPoSCancel = !pwallet->CreateStakeTransaction (*pblock, txNew, nPosReward);
        if (fPoSCancel) return nullptr;
        pblock->vtx.push_back(MakeTransactionRef(std::move(txNew)));
    }

    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization).
    // Note that the mempool would accept transactions with witness data before
    // IsWitnessEnabled, but we would only ever mine blocks after IsWitnessEnabled
    // unless there is a massive block reorganization with the witness softfork
    // not activated.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus()) && fMineWitnessTx;

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);

    int64_t nTime1 = GetTimeMicros();

    nLastBlockTx = nBlockTx;
    nLastBlockWeight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    if (pblock->IsProofOfStake()) {
        int ind = (pblock->vtx[1]->vout.size() < 2) ? 0 : 1;
        coinbaseTx.vout[0].scriptPubKey = pblock->vtx[1]->vout[ind].scriptPubKey;
        coinbaseTx.vout[0].nValue = nFees + nPosReward;
    } else {
        coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
        coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    }
    coinbaseTx.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(OP_0)) + COINBASE_FLAGS;
    FillBlockPayments(coinbaseTx, nHeight, coinbaseTx.vout[0].nValue);
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    bool fHaveWitness = false;
    for (const auto& tx : pblock->vtx) {
        if (tx->HasWitness()) { fHaveWitness = true; break; }
    }
    if (fHaveWitness)
        pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
    if (pblock->IsProofOfStake()) {
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        fPoSCancel = !pwallet->SignBlock(*pblock);
        if (fPoSCancel) return nullptr;
    }
    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    for (CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && it->GetTx().HasWitness())
            return false;
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    uint64_t nExtra;
    GetRandBytes((unsigned char*)&nExtra, sizeof(nExtra));
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << nExtra << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

#ifdef ENABLE_WALLET

// PoW mining

std::atomic<int> POWCount{0};
std::atomic<int> POWWorked{0};
CScript POWScript;
std::atomic<bool> isready{false};

void POWMinerThread (int POWIndex) {
    LogPrintf("POWMinerThread %d started\n", POWIndex);
    RenameThread("coin-pow-miner");
    POWWorked++;
    unsigned int extra = POWIndex << 24;
    int POWTries = 0x0000FFFF;
    int skip = 0;
    try {
        while (true) {
            if (ShutdownRequested()) break;
            if (POWIndex > POWCount) break;
            if (!isready) {
                if (IsInitialBlockDownload()) { MilliSleep(1000); continue; } else { isready = true; }
            }
            if (skip > 0) { skip--; MilliSleep(1000); continue; };
            int count = 0;
            if (g_connman) g_connman->ForEachNode([&count](CNode* pnode) { count++; });
            if (!g_connman || (count < 3)) { skip = 5; continue; };
            int64_t nTime = GetTimeMillis();
            try {
                std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(POWScript));
                if (!pblocktemplate.get()) continue;
                CBlock *pblock = &pblocktemplate->block;
                IncrementExtraNonce(pblock, chainActive.Tip(), extra);
                int nMaxTries = POWTries;
                bool fNegative, fOverflow;
                arith_uint256 bnTarget;
                bnTarget.SetCompact (pblock->nBits, &fNegative, &fOverflow);
                while ((nMaxTries > 0) && (UintToArith256(pblock->GetPoWHash()) >= bnTarget)) {
                    pblock->nNonce++;
                    nMaxTries--;
                }
                nTime = GetTimeMillis() - nTime; if (nTime < 1) nTime = 1;
                LogPrintf("POWMinerThread %d speed is %d kb\n", POWIndex, (POWTries-nMaxTries) / nTime);
                if ((nTime < 15000) || (nTime > 45000)) {
                    POWTries = ((POWTries-nMaxTries) / nTime) * 30000;
                    if (POWTries < 0x00000FFF) POWTries = 0x00000FFF;
                }
                if (nMaxTries == 0) { continue; }
                if (UintToArith256(pblock->GetPoWHash()) >= bnTarget) { continue; }
                std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
                if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr))
                    LogPrintf("POWMinerThread: ProcessNewBlock, block not accepted...\n");
                extra = POWIndex << 24;
            } catch (...) {
                PrintExceptionContinue(NULL, "POWMinerThread()->CreateNewBlock");
            }
        };
    }
    catch (const boost::thread_interrupted&) {
        POWWorked--;
        LogPrintf("POWMinerThread terminated\n");
        return;
    }
    catch (const std::runtime_error &e) {
        POWWorked--;
        LogPrintf("POWMinerThread runtime error: %s\n", e.what());
        return;
    } catch (...) {
        PrintExceptionContinue(NULL, "POWMinerThread()");
    }
    POWWorked--;
    LogPrintf("POWMinerThread %d stopped\n", POWIndex);
}

int generatePoWCoin (int nThreads) {
    if (nThreads < 0) { nThreads = std::thread::hardware_concurrency(); }
    if (nThreads > 255) { return POWCount; }
    if (POWCount > 0) {
        POWCount = 0;
        while (POWWorked > 0) MilliSleep(100);
    }
    if (nThreads == 0) return 0;
    if (GetWallets().size() == 0) return 0;
    std::shared_ptr<CWallet> pwallet = GetWallets().front();
    std::shared_ptr<CReserveScript> coinbase;
    pwallet->GetScriptForMining (coinbase);
    if (!coinbase) return 0;
    if (coinbase->reserveScript.empty()) return 0;
    POWScript = coinbase->reserveScript;
    CTxDestination Addr;
    if (ExtractDestination(POWScript, Addr)) { LogPrintf("POWMiner to %s\n", EncodeDestination(Addr)); }
    for (int i = 1; i <= nThreads; i++) {
        POWCount++;
        std::thread newthread (POWMinerThread, i);
        newthread.detach();
    }
    return POWCount;
}

// PoS mining

std::atomic<int> POSCount{0};
std::atomic<int> POSWorked{0};

void POSMinerThread (int POSIndex) {
    LogPrintf("POSMinerThread %d started\n", POSIndex);
    RenameThread("coin-pos-miner");
    POSWorked++;
    int skip = 0;
    int index = 0;
    try {
        while (true) {
            if (ShutdownRequested()) break;
            if (POSIndex > POSCount) break;
            if (!isready) {
                if (IsInitialBlockDownload()) { MilliSleep(1000); continue; } else { isready = true; }
            }
            if (skip > 0) { skip--; MilliSleep(1000); continue; };
            if (!masternodeSync.IsSynced()) { skip = 5; continue; };
            int count = 0;
            if (g_connman) g_connman->ForEachNode([&count](CNode* pnode) { count++; });
            if (!g_connman || (count < 3)) { skip = 5; continue; };
            std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
            if (wallets.size() == 0) { skip = 5; continue; };
            if (++index > wallets.size()) index = 1;
            std::shared_ptr<CWallet> pwallet = wallets[index-1];
            if (pwallet->IsLocked(true)) { skip = 3; continue; };
            try {
                bool fPoSCancel = false;
                std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewPoSBlock(fPoSCancel, pwallet));
                if (fPoSCancel) { skip = 3; continue; }
                if (!pblocktemplate.get()) continue;
                CBlock *pblock = &pblocktemplate->block;
                LogPrintf("POSMinerThread: proof-of-stake block found %s\n", pblock->GetHash().ToString());
                std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
                if (ProcessNewBlock(Params(), shared_pblock, true, nullptr)) { skip = 30; };
            } catch (...) {
                PrintExceptionContinue(NULL, "POSMinerThread()");
            }
            skip = 1;
        }
    }
    catch (const boost::thread_interrupted&) {
        POSWorked--;
        LogPrintf("POSMinerThread terminated\n");
        return;
    } catch (const std::runtime_error &e) {
        POSWorked--;
        LogPrintf("POSMinerThread runtime error: %s\n", e.what());
        return;
    } catch (...) {
        PrintExceptionContinue(NULL, "POSMinerThread()");
    }
    POSWorked--;
    LogPrintf("POSMinerThread %d stopped\n", POSIndex);
}

int generatePoSCoin (int nThreads) {
    if (nThreads < 0) { nThreads = GetWallets().size(); }
    if (nThreads > 255) { return POSCount; }
    if (nThreads > GetWallets().size()) { nThreads = GetWallets().size(); }
    if (POSCount > 0) {
        POSCount = 0;
        while (POSWorked > 0) MilliSleep(100);
    }
    if (nThreads == 0) return 0;
    if (GetWallets().size() == 0) return 0;
    for (int i = 1; i <= nThreads; i++) {
        POSCount++;
        std::thread newthread (POSMinerThread, i);
        newthread.detach();
    }
    return POSCount;
}

int generateCoin (int nThreads) {
    if (nThreads < 0) { generatePoWCoin (0); generatePoSCoin (0); }
    if (nThreads == 0) { generatePoWCoin (0); generatePoSCoin (1); }
    if ((nThreads > 0) && (nThreads < 63)) {
        generatePoSCoin (0);
        int prc = std::thread::hardware_concurrency();
        if (nThreads >= prc) nThreads = prc - 1;
        if (nThreads <= 1) nThreads = 1;
        generatePoWCoin (nThreads);
    }
    if (POSCount > 0) { uiInterface.NotifyGenerateStateChanged(-POSCount); } else
    if (POWCount > 0) { uiInterface.NotifyGenerateStateChanged(POWCount); } else
                      { uiInterface.NotifyGenerateStateChanged(0); }
    if (POSCount > 0) return 0;
    if (POWCount > 0) return POWCount;
    return -1;
}

#endif // ENABLE_WALLET
