// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/consensus.h>
#include <core_io.h>
#include <key_io.h>
#include <index/txindex.h>
#include <shutdown.h>
#include <ui_interface.h>
#include <util.h>
#include <validation.h>

#include <boost/thread.hpp>

constexpr char DB_TXINDEX = 't';
constexpr char DB_ADDRESS = 'a';

std::unique_ptr<TxIndex> g_txindex;

struct CDiskTxPos : public CDiskBlockPos
{
    unsigned int nTxOffset; // after header

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(CDiskBlockPos, *this);
        READWRITE(VARINT(nTxOffset));
    }

    CDiskTxPos(const CDiskBlockPos &blockIn, unsigned int nTxOffsetIn) : CDiskBlockPos(blockIn.nFile, blockIn.nPos), nTxOffset(nTxOffsetIn) {
    }

    CDiskTxPos() {
        SetNull();
    }

    void SetNull() {
        CDiskBlockPos::SetNull();
        nTxOffset = 0;
    }
};

class CAddressKey {
public:
    CScript script{};
    COutPoint out{};

    CAddressKey(const COutPoint& pout = COutPoint()) : out(pout) { }
    CAddressKey(const CScript& pscript, const COutPoint& pout = COutPoint()) {
        script = pscript;
        out = pout;
        if (script.size() == 67 && script[0] == 65 && script.back() == OP_CHECKSIG) {
            CTxDestination ar;
            if (ExtractDestination(script, ar)) script = GetScriptForDestination(ar);
        }
        if (script.size() == 35 && script[0] == 33 && script.back() == OP_CHECKSIG) {
            CTxDestination ar;
            if (ExtractDestination(script, ar)) script = GetScriptForDestination(ar);
        }
    }

    CAddressKey(const CAddressKey &pp) {
        script = pp.script;
        out = pp.out;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(script);
        READWRITE(out);
    }

    friend bool operator<(const CAddressKey& a, const CAddressKey& b) {
        return (a.script == b.script) ? (a.out < b.out) : (a.script < b.script);
    }

    friend bool operator==(const CAddressKey& a, const CAddressKey& b) {
        return (a.script == b.script) && (a.out == b.out);
    }

    friend bool operator!=(const CAddressKey& a, const CAddressKey& b) {
        return !(a == b);
    }

    std::string GetAddr () const {
        CTxDestination ar;
        if (ExtractDestination (script, ar)) return EncodeDestination(ar);
        return ScriptToAsmStr (script);
    }
};

class CAddressValue {
public:
    char mode{0}; // 0 - UNK, 1 - COIN, 2 - COINBASE, 3 - SPEND, 4 - FULL,
    CAmount value{0};
    uint32_t height{0};
    uint32_t spend_height{0};
    COutPoint spend_out{};
    uint256 block_hash{};

    CAddressValue() {};

    CAddressValue(CAmount avalue, const uint256& ablock_hash, bool aiscoinbase) :
        mode(aiscoinbase ? 2/*COINBASE*/ : 1/*COIN*/), value(avalue), block_hash(ablock_hash) {}

    CAddressValue(const uint256& aspend_block_hash, const COutPoint& aspend_out) :
        mode(3/*SPEND*/), block_hash(aspend_block_hash), spend_out(aspend_out) {}

    CAddressValue(CAmount avalue, uint32_t aheight, uint32_t aspend_height, const COutPoint& aspend_out) :
        mode(4/*FULL*/), value(avalue), height(aheight), spend_height(aspend_height), spend_out(aspend_out) {}

    CAddressValue(const CAddressValue &pp) {
        mode = pp.mode;
        value = pp.value;
        height = pp.height;
        spend_height = pp.spend_height;
        spend_out = pp.spend_out;
        block_hash = pp.block_hash;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mode);
        READWRITE(value);
        if (mode == 4/*FULL*/) {
            READWRITE(height);
            READWRITE(spend_height);
        } else {
            READWRITE(block_hash);
        }
        if ((mode == 4/*FULL*/) || (mode == 3/*SPEND*/))
            READWRITE(spend_out);
    }
};

/**
 * Access to the txindex database (indexes/txindex/)
 *
 * The database stores a block locator of the chain the database is synced to
 * so that the TxIndex can efficiently determine the point it last stopped at.
 * A locator is used instead of a simple hash of the chain tip because blocks
 * and block index entries may not be flushed to disk until after this database
 * is updated.
 */
class TxIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    /// Read the disk location of the transaction data with the given hash. Returns false if the
    /// transaction hash is not indexed.
    bool ReadTxPos(const uint256& txid, CDiskTxPos& pos) const {
        return Read(std::make_pair(DB_TXINDEX, txid), pos);
    }
    bool ReadAddress (const CAddressKey& key, CAddressValue& value) const {
        return Read(std::make_pair(DB_ADDRESS, key), value);
    }
    bool ReadAddress (const CScript& script, std::map<CAddressKey, CAddressValue>& vec);

    /// Write a batch of transaction positions to the DB.
    bool Writes(const std::vector<std::pair<uint256, CDiskTxPos>>& txs, 
                const std::vector<std::pair<CAddressKey, CAddressValue>>& addresses);

    void Optimize();
};

TxIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(GetDataDir() / "indexes", n_cache_size, f_memory, f_wipe)
{}

bool TxIndex::DB::ReadAddress (const CScript& script, std::map<CAddressKey, CAddressValue>& vec) {
    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(std::make_pair(DB_ADDRESS, CAddressKey(script)));
    while (pcursor->Valid()) {
        std::pair<char, CAddressKey> key;
        if (pcursor->GetKey(key) && (key.first == DB_ADDRESS) && key.second.script == script) {
            CAddressValue value;
            if (pcursor->GetValue(value)) {
                vec[key.second] = value;
                pcursor->Next();
            } else {
                return error("failed to get address index value");
            }
        } else {
            break;
        }
    }
    return true;
}

bool TxIndex::DB::Writes (const std::vector<std::pair<uint256, CDiskTxPos> >& txs,
            const std::vector<std::pair<CAddressKey, CAddressValue>>& addresses) {
    CDBBatch batch(*this);
    for (auto& it : txs)
        batch.Write(std::make_pair(DB_TXINDEX, it.first), it.second);
    for (auto& it : addresses) {
        if (it.second.mode == 0) {
            batch.Erase(std::make_pair(DB_ADDRESS, it.first));
        } else {
            batch.Write(std::make_pair(DB_ADDRESS, it.first), it.second);
        }
    }
    return WriteBatch(batch);
}

void TxIndex::DB::Optimize() {
    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(std::make_pair(DB_ADDRESS, CAddressKey()));
    int hei = chainActive.Height();
    std::vector<std::pair<CAddressKey, CAddressValue>> addressKeyValue;
    int nn = 0;
    while (pcursor->Valid()) {
        std::pair<char, CAddressKey> key;
        if (!(pcursor->GetKey(key) && (key.first == DB_ADDRESS))) break;
        if (key.second.script == CScript()) { pcursor->Next(); continue; }
        CAddressValue value;
        if (!pcursor->GetValue(value)) break;
        pcursor->Next();
        if (value.mode != 4/*FULL*/) {
            LOCK(cs_main);
            CBlockIndex* bi = LookupBlockIndex(value.block_hash);
            if (!chainActive.Contains(bi) || (hei - bi->nHeight < 10000)) continue;
            CAddressValue spvalue;
            ReadAddress (CAddressKey(key.second.out), spvalue);
            if (spvalue.mode != 3/*SPEND*/) continue;
            CBlockIndex* bis = LookupBlockIndex(spvalue.block_hash);
            if (!chainActive.Contains(bis) || (hei - bis->nHeight < 10000)) continue;
            if (addressKeyValue.size() > 10000) { Writes({}, addressKeyValue); nn += addressKeyValue.size(); addressKeyValue.clear(); }
            addressKeyValue.push_back(std::make_pair(key.second, CAddressValue(value.value, bi->nHeight, bis->nHeight, spvalue.spend_out)));
            addressKeyValue.push_back(std::make_pair(CAddressKey(key.second.out), CAddressValue()));
            if (nn > 250000) {
                LogPrintf("Compacting indexes record number %d\n", nn);
                nn = 0;
            }

        }
    }
    if (addressKeyValue.size() > 0) {
        Writes({}, addressKeyValue); 
        LogPrintf("Compacting indexes record number %d\n", nn);
    }
}

TxIndex::TxIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_db(MakeUnique<TxIndex::DB>(n_cache_size, f_memory, f_wipe))
{}

TxIndex::~TxIndex() {}

bool TxIndex::PostThread()
{
    m_db->Optimize();
    return BaseIndex::PostThread();
}

bool TxIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex) {
    if ((pindex->nHeight & 0x3F) == 0) FindAddress ({});
    std::vector<std::pair<uint256, CDiskTxPos> > txKeyValue;
    txKeyValue.reserve(block.vtx.size());
    std::vector<std::pair<CAddressKey, CAddressValue>> addressKeyValue;
    addressKeyValue.reserve(block.vtx.size());
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    for (const auto& tx : block.vtx) {
        uint256 hash = tx->GetHash();
        for (size_t j = 0; j < tx->vin.size(); j++) {
            if (tx->IsCoinBase()) break;
            addressKeyValue.push_back(std::make_pair(CAddressKey(tx->vin[j].prevout),
                        CAddressValue(pindex->GetBlockHash(), COutPoint(hash, j))));
        }
        for (unsigned int k = 0; k < tx->vout.size(); k++) {
            const CTxOut &out = tx->vout[k];
            if (out.scriptPubKey.IsUnspendable()) continue;
            addressKeyValue.push_back(std::make_pair(CAddressKey(out.scriptPubKey, COutPoint(hash, k)),
                        CAddressValue(out.nValue, pindex->GetBlockHash(), tx->IsCoinBase())));
        }
        txKeyValue.emplace_back(tx->GetHash(), pos);
        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION);
    }
    return m_db->Writes(txKeyValue, addressKeyValue);
}

bool TxIndex::UnWriteBlock(const CBlock& block, const CBlockIndex* pindex) {
    std::vector<std::pair<CAddressKey, CAddressValue>> addressKeyValue;
    addressKeyValue.reserve(block.vtx.size());

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();

        // delete outputs
        for (size_t k = 0; k < tx.vout.size(); k++) {
            auto& out = tx.vout[k];
            if (out.scriptPubKey.IsUnspendable()) continue;
            addressKeyValue.push_back(std::make_pair(CAddressKey(out.scriptPubKey, COutPoint(hash, k)), CAddressValue()));
        }

        // delete inputs spent
        for (size_t j = 0; j < tx.vin.size(); j++) {
            if (tx.IsCoinBase()) break;
            addressKeyValue.push_back(std::make_pair(CAddressKey(tx.vin[j].prevout), CAddressValue()));
        }
    }

    return m_db->Writes({}, addressKeyValue);
}

BaseIndex::DB& TxIndex::GetDB() const { return *m_db; }

bool TxIndex::FindTx(const uint256& tx_hash, uint256& block_hash, CTransactionRef& tx) {
    CDiskTxPos postx;
    if (!m_db->ReadTxPos(tx_hash, postx)) {
        return false;
    }

    CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        return error("%s: OpenBlockFile failed", __func__);
    }
    CBlockHeader header;
    try {
        file >> header;
        if (fseek(file.Get(), postx.nTxOffset, SEEK_CUR)) {
            return error("%s: fseek(...) failed", __func__);
        }
        file >> tx;
    } catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    if (tx->GetHash() != tx_hash) {
        return error("%s: txid mismatch", __func__);
    }
    block_hash = header.GetHash();
    return true;
}

CAddressInfo TxIndex::FindAddress (const CScript& script, int total_max) {
    static std::map<CScript, CAddressInfo> cached_data;
    static CCriticalSection cached_lock{};
    static int cached_hei{-1};

    if (IsInitialBlockDownload()) return CAddressInfo();
    LOCK(cached_lock);
    int hei = chainActive.Height();
    if (hei != cached_hei) cached_data.clear();
    if (cached_data.count(script) > 0) return cached_data[script];
    if (script == CScript()) return CAddressInfo();

    CAddressInfo data;
    std::map<CAddressKey, CAddressValue> retmap;
    m_db->ReadAddress(script, retmap);
    data.receive_amount = data.send_amount = 0;
    data.total_in = data.total_out = 0;
    data.height = hei;
    data.data.reserve (std::min((int)retmap.size() * 2, 1000));
    std::vector<std::pair<CAddressKey, CAddressValue>> addressKeyValue;
    for (const auto& it : retmap) {
        uint32_t receive_height = it.second.height;
        uint32_t spend_height = it.second.spend_height;
        COutPoint spend_out = it.second.spend_out;
        if (it.second.mode != 4/*FULL*/) {
            LOCK(cs_main);
            CBlockIndex* bi = LookupBlockIndex(it.second.block_hash);
            if (!chainActive.Contains(bi)) {
                LogPrintf("____FindAddress: not hash (%s) in chain\n", it.second.block_hash.ToString());
                continue;
            };
            receive_height = bi->nHeight;
            CAddressValue spvalue;
            m_db->ReadAddress (CAddressKey(it.first.out), spvalue);
            if (spvalue.mode == 3/*SPEND*/) {
                CBlockIndex* bis = LookupBlockIndex(spvalue.block_hash);
                if (chainActive.Contains(bis)) {
                    spend_height = bis->nHeight;
                    spend_out = spvalue.spend_out;
                } else { LogPrintf("____FindAddress: not hash (%s) in chain\n", spvalue.block_hash.ToString()); }
            }
        }
        data.total_in++;
        data.receive_amount += it.second.value;
        if (spend_height > 0) {
            data.total_out++;
            data.send_amount += it.second.value;
        }
        if ((it.second.mode != 4/*FULL*/) && (spend_height > 0) && (hei - spend_height > 10000)) {
            addressKeyValue.push_back(std::make_pair(it.first, CAddressValue(it.second.value,
                receive_height, spend_height, spend_out)));
            addressKeyValue.push_back(std::make_pair(CAddressKey(it.first.out), CAddressValue()));
            if (addressKeyValue.size() > 10000) { m_db->Writes({}, addressKeyValue); addressKeyValue.clear(); }
        }
        if ((spend_height != 0) && (total_max > 0) && (data.total_out > total_max)) continue;
        data.data.push_back (CAddressInfoItem(it.first.script, it.second.value, receive_height,
            it.first.out.hash, it.first.out.n, (spend_height > 0) ? CAddressInfoState::SPEND : (
                ((it.second.mode == 2/*COINBASE*/) && ((receive_height + COINBASE_MATURITY) > hei)) ?
                    CAddressInfoState::MATURE : CAddressInfoState::RECEIVE)));
        if (spend_height > 0)
            data.data.push_back (CAddressInfoItem(it.first.script, it.second.value, spend_height,
                spend_out.hash, spend_out.n, CAddressInfoState::SEND));
    }
    if (addressKeyValue.size() > 0) m_db->Writes({}, addressKeyValue);
    std::sort(data.data.begin(), data.data.end(), [](const CAddressInfoItem& l, const CAddressInfoItem& r) {
        return (l.height == r.height) ? (int)l.state - (int)r.state : l.height > r.height; });
    cached_data[script] = data;
    cached_hei = hei;
    return data;
}
