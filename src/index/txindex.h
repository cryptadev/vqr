// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_TXINDEX_H
#define BITCOIN_INDEX_TXINDEX_H

#include <chain.h>
#include <index/base.h>
#include <txdb.h>

enum CAddressInfoState { RECEIVE, MATURE, SPEND, SEND };

struct CAddressInfoItem {
    CScript script{};
    CAmount value{0};
    uint32_t height{0};
    uint256 tx_hash{};
    uint32_t tx_out{0};
    CAddressInfoState state{CAddressInfoState::RECEIVE};

    CAddressInfoItem (const CScript& ascript, CAmount avalue, uint32_t aheight, const uint256& atx_hash, uint32_t atx_out,
        CAddressInfoState astate) : script(ascript), value(avalue), height(aheight), tx_hash(atx_hash), tx_out(atx_out),
            state(astate) { };
};

struct CAddressInfo {
    CAmount receive_amount{0}, send_amount{0};
    int total_in{0}, total_out{0}, height{0};
    std::vector<CAddressInfoItem> data{};
};

/**
 * TxIndex is used to look up transactions included in the blockchain by hash.
 * The index is written to a LevelDB database and records the filesystem
 * location of each transaction by transaction hash.
 */
class TxIndex final : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;

protected:
    /// Override base class init to migrate from old database.
    bool PostThread() override;

    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;
    bool UnWriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    BaseIndex::DB& GetDB() const override;

    const char* GetName() const override { return "indexes"; }

public:
    /// Constructs the index, which becomes available to be queried.
    explicit TxIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    // Destructor is declared because this class contains a unique_ptr to an incomplete type.
    virtual ~TxIndex() override;

    /// Look up a transaction by hash.
    ///
    /// @param[in]   tx_hash  The hash of the transaction to be returned.
    /// @param[out]  block_hash  The hash of the block the transaction is found in.
    /// @param[out]  tx  The transaction itself.
    /// @return  true if transaction is found, false otherwise
    bool FindTx(const uint256& tx_hash, uint256& block_hash, CTransactionRef& tx);
    CAddressInfo FindAddress (const CScript& script, int total_max = 5000);
};

/// The global transaction index, used in GetTransaction. May be null.
extern std::unique_ptr<TxIndex> g_txindex;

#endif // BITCOIN_INDEX_TXINDEX_H
