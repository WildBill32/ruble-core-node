// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <script/descriptor.h>
#include <script/sign.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace util::hex_literals;
using util::Split;

namespace {

void CheckUnparsable(const std::string& prv, const std::string& pub, const std::string& expected_error)
{
    FlatSigningProvider keys_priv, keys_pub;
    std::string error;
    auto parse_priv = Parse(prv, keys_priv, error);
    auto parse_pub = Parse(pub, keys_pub, error);
    BOOST_CHECK_MESSAGE(parse_priv.empty(), prv);
    BOOST_CHECK_MESSAGE(parse_pub.empty(), pub);
    BOOST_CHECK_EQUAL(error, expected_error);
}

/** Check that the script is inferred as non-standard */
void CheckInferRaw(const CScript& script)
{
    FlatSigningProvider dummy_provider;
    std::unique_ptr<Descriptor> desc = InferDescriptor(script, dummy_provider);
    BOOST_CHECK(desc->ToString().rfind("raw(", 0) == 0);
}

constexpr int DEFAULT = 0;
constexpr int RANGE = 1; // Expected to be ranged descriptor
constexpr int HARDENED = 2; // Derivation needs access to private keys
constexpr int UNSOLVABLE = 4; // This descriptor is not expected to be solvable
constexpr int SIGNABLE = 8; // We can sign with this descriptor (this is not true when actual BIP32 derivation is used, as that's not integrated in our signing code)
constexpr int DERIVE_HARDENED = 16; // The final derivation is hardened, i.e. ends with *' or *h
constexpr int MIXED_PUBKEYS = 32;
constexpr int XONLY_KEYS = 64; // X-only pubkeys are in use (and thus inferring/caching may swap parity of pubkeys/keyids)
constexpr int MISSING_PRIVKEYS = 128; // Not all private keys are available, so ToPrivateString will fail.
constexpr int SIGNABLE_FAILS = 256; // We can sign with this descriptor, but actually trying to sign will fail

/** Compare two descriptors. If only one of them has a checksum, the checksum is ignored. */
bool EqualDescriptor(std::string a, std::string b)
{
    bool a_check = (a.size() > 9 && a[a.size() - 9] == '#');
    bool b_check = (b.size() > 9 && b[b.size() - 9] == '#');
    if (a_check != b_check) {
        if (a_check) a = a.substr(0, a.size() - 9);
        if (b_check) b = b.substr(0, b.size() - 9);
    }
    return a == b;
}

bool EqualSigningProviders(const FlatSigningProvider& a, const FlatSigningProvider& b)
{
    return a.scripts == b.scripts
        && a.pubkeys == b.pubkeys
        && a.origins == b.origins
        && a.keys == b.keys
        && a.tr_trees == b.tr_trees;
}

std::string UseHInsteadOfApostrophe(const std::string& desc)
{
    std::string ret = desc;
    while (true) {
        auto it = ret.find('\'');
        if (it == std::string::npos) break;
        ret[it] = 'h';
    }

    // GetDescriptorChecksum returns "" if the checksum exists but is bad.
    // Switching apostrophes with 'h' breaks the checksum if it exists - recalculate it and replace the broken one.
    if (GetDescriptorChecksum(ret) == "") {
        ret = ret.substr(0, desc.size() - 9);
        ret += std::string("#") + GetDescriptorChecksum(ret);
    }
    return ret;
}

// Count the encoded Ruble mainnet extended public keys in a descriptor.
static size_t CountExtPubs(const std::string& desc)
{
    size_t count = 0;
    size_t p = desc.find("rpub", 0);
    while (p != std::string::npos) {
        count++;
        p = desc.find("rpub", p + 1);
    }
    return count;
}

const std::set<std::vector<uint32_t>> ONLY_EMPTY{{}};

std::set<CPubKey> GetKeyData(const FlatSigningProvider& provider, int flags) {
    std::set<CPubKey> ret;
    for (const auto& [_, pubkey] : provider.pubkeys) {
        if (flags & XONLY_KEYS) {
            unsigned char bytes[33];
            BOOST_CHECK_EQUAL(pubkey.size(), 33);
            std::copy(pubkey.begin(), pubkey.end(), bytes);
            bytes[0] = 0x02;
            CPubKey norm_pubkey{bytes};
            ret.insert(norm_pubkey);
        } else {
            ret.insert(pubkey);
        }
    }
    return ret;
}

std::set<std::pair<CPubKey, KeyOriginInfo>> GetKeyOriginData(const FlatSigningProvider& provider, int flags) {
    std::set<std::pair<CPubKey, KeyOriginInfo>> ret;
    for (const auto& [_, data] : provider.origins) {
        if (flags & XONLY_KEYS) {
            unsigned char bytes[33];
            BOOST_CHECK_EQUAL(data.first.size(), 33);
            std::copy(data.first.begin(), data.first.end(), bytes);
            bytes[0] = 0x02;
            CPubKey norm_pubkey{bytes};
            KeyOriginInfo norm_origin = data.second;
            std::fill(std::begin(norm_origin.fingerprint), std::end(norm_origin.fingerprint), 0); // fingerprints don't necessarily match.
            ret.emplace(norm_pubkey, norm_origin);
        } else {
            ret.insert(data);
        }
    }
    return ret;
}

void DoCheck(std::string prv, std::string pub, const std::string& norm_pub, int flags,
             const std::vector<std::vector<std::string>>& scripts, const std::optional<OutputType>& type, std::optional<uint256> op_desc_id = std::nullopt,
             const std::set<std::vector<uint32_t>>& paths = ONLY_EMPTY, bool replace_apostrophe_with_h_in_prv=false,
             bool replace_apostrophe_with_h_in_pub=false, uint32_t spender_nlocktime=0, uint32_t spender_nsequence=CTxIn::SEQUENCE_FINAL,
             std::map<std::vector<uint8_t>, std::vector<uint8_t>> preimages={},
             std::optional<std::string> expected_prv = std::nullopt, std::optional<std::string> expected_pub = std::nullopt, int desc_index = 0)
{
    FlatSigningProvider keys_priv, keys_pub;
    std::set<std::vector<uint32_t>> left_paths = paths;
    std::string error;

    std::vector<std::unique_ptr<Descriptor>> parse_privs;
    std::vector<std::unique_ptr<Descriptor>> parse_pubs;
    // Check that parsing succeeds.
    if (replace_apostrophe_with_h_in_prv) {
        prv = UseHInsteadOfApostrophe(prv);
    }
    parse_privs = Parse(prv, keys_priv, error);
    BOOST_CHECK_MESSAGE(!parse_privs.empty(), error);
    if (replace_apostrophe_with_h_in_pub) {
        pub = UseHInsteadOfApostrophe(pub);
    }
    parse_pubs = Parse(pub, keys_pub, error);
    BOOST_CHECK_MESSAGE(!parse_pubs.empty(), error);

    auto& parse_priv = parse_privs.at(desc_index);
    auto& parse_pub = parse_pubs.at(desc_index);

    // We must be able to estimate the max satisfaction size for any solvable descriptor top descriptor (but combo).
    const bool is_nontop_or_nonsolvable{!parse_priv->IsSolvable() || !parse_priv->GetOutputType()};
    const auto max_sat_maxsig{parse_priv->MaxSatisfactionWeight(true)};
    const auto max_sat_nonmaxsig{parse_priv->MaxSatisfactionWeight(false)};
    BOOST_CHECK(max_sat_nonmaxsig <= max_sat_maxsig);
    const auto max_elems{parse_priv->MaxSatisfactionElems()};
    const bool is_input_size_info_set{max_sat_maxsig && max_sat_nonmaxsig && max_elems};
    BOOST_CHECK_MESSAGE(is_input_size_info_set || is_nontop_or_nonsolvable, prv);

    // The ScriptSize() must match the size of the Script string. (ScriptSize() is set for all descs but 'combo()'.)
    const bool is_combo{!parse_priv->IsSingleType()};
    BOOST_CHECK_MESSAGE(is_combo || parse_priv->ScriptSize() == scripts[0][0].size() / 2, "Invalid ScriptSize() for " + prv);

    // Check that the correct OutputType is inferred
    BOOST_CHECK(parse_priv->GetOutputType() == type);
    BOOST_CHECK(parse_pub->GetOutputType() == type);

    // Check private keys are extracted from the private version but not the public one.
    BOOST_CHECK(keys_priv.keys.size());
    BOOST_CHECK(!keys_pub.keys.size());

    // If expected_pub is provided, check that the serialize matches that.
    // Otherwise check that they serialize back to the public version.
    std::string pub1 = parse_priv->ToString();
    std::string pub2 = parse_pub->ToString();
    if (expected_pub) {
        BOOST_CHECK_MESSAGE(EqualDescriptor(*expected_pub, pub1), "Private ser: " + pub1 + " Public desc: " + *expected_pub);
        BOOST_CHECK_MESSAGE(EqualDescriptor(*expected_pub, pub2), "Public ser: " + pub2 + " Public desc: " + *expected_pub);
    } else {
        BOOST_CHECK_MESSAGE(EqualDescriptor(pub, pub1), "Private ser: " + pub1 + " Public desc: " + pub);
        BOOST_CHECK_MESSAGE(EqualDescriptor(pub, pub2), "Public ser: " + pub2 + " Public desc: " + pub);
    }

    // Check that the COMPAT identifier did not change
    if (op_desc_id) {
        BOOST_CHECK_MESSAGE(DescriptorID(*parse_priv) == *op_desc_id, "DescriptorID() " + DescriptorID(*parse_priv).ToString() + " does not match for priv " + prv);
    }

    // Check that both can be serialized with private key back to the private version, but not without private key.
    if (!(flags & MISSING_PRIVKEYS)) {
        std::string prv1;
        BOOST_CHECK(parse_priv->ToPrivateString(keys_priv, prv1));
        if (expected_prv) {
            BOOST_CHECK_MESSAGE(EqualDescriptor(*expected_prv, prv1), "Private ser: " + prv1 + "Private desc: " + *expected_prv);
        } else {
            BOOST_CHECK_MESSAGE(EqualDescriptor(prv, prv1), "Private ser: " + prv1 + " Private desc: " + prv);
        }
        BOOST_CHECK(!parse_priv->ToPrivateString(keys_pub, prv1));
        BOOST_CHECK(parse_pub->ToPrivateString(keys_priv, prv1));
        if (expected_prv) {
            BOOST_CHECK(EqualDescriptor(*expected_prv, prv1));
            BOOST_CHECK_MESSAGE(EqualDescriptor(*expected_prv, prv1), "Private ser: " + prv1 + " Private desc: " + *expected_prv);
        } else {
            BOOST_CHECK_MESSAGE(EqualDescriptor(prv, prv1), "Private ser: " + prv1 + " Private desc: " + prv);
        }
        BOOST_CHECK(!parse_pub->ToPrivateString(keys_pub, prv1));

        // Check that both can ExpandPrivate and get the same SigningProviders
        FlatSigningProvider priv_prov;
        parse_priv->ExpandPrivate(0, keys_priv, priv_prov);

        FlatSigningProvider pub_prov;
        parse_pub->ExpandPrivate(0, keys_priv, pub_prov);

        BOOST_CHECK_MESSAGE(EqualSigningProviders(priv_prov, pub_prov), "Private desc: " + prv + " Pub desc: " + pub);
    }

    // Check that private can produce the normalized descriptors
    std::string norm1;
    BOOST_CHECK(parse_priv->ToNormalizedString(keys_priv, norm1));
    BOOST_CHECK_MESSAGE(EqualDescriptor(norm1, norm_pub), "priv->ToNormalizedString(): " + norm1 + " Norm. desc: " + norm_pub);
    BOOST_CHECK(parse_pub->ToNormalizedString(keys_priv, norm1));
    BOOST_CHECK_MESSAGE(EqualDescriptor(norm1, norm_pub), "pub->ToNormalizedString(): " + norm1 + " Norm. desc: " + norm_pub);

    // Check whether IsRange on both returns the expected result
    BOOST_CHECK_EQUAL(parse_pub->IsRange(), (flags & RANGE) != 0);
    BOOST_CHECK_EQUAL(parse_priv->IsRange(), (flags & RANGE) != 0);

    // * For ranged descriptors,  the `scripts` parameter is a list of expected result outputs, for subsequent
    //   positions to evaluate the descriptors on (so the first element of `scripts` is for evaluating the
    //   descriptor at 0; the second at 1; and so on). To verify this, we evaluate the descriptors once for
    //   each element in `scripts`.
    // * For non-ranged descriptors, we evaluate the descriptors at positions 0, 1, and 2, but expect the
    //   same result in each case, namely the first element of `scripts`. Because of that, the size of
    //   `scripts` must be one in that case.
    if (!(flags & RANGE)) assert(scripts.size() == 1);
    size_t max = (flags & RANGE) ? scripts.size() : 3;

    // Iterate over the position we'll evaluate the descriptors in.
    for (size_t i = 0; i < max; ++i) {
        // Call the expected result scripts `ref`.
        const auto& ref = scripts[(flags & RANGE) ? i : 0];
        // When t=0, evaluate the `prv` descriptor; when t=1, evaluate the `pub` descriptor.
        for (int t = 0; t < 2; ++t) {
            // When the descriptor is hardened, evaluate with access to the private keys inside.
            const FlatSigningProvider& key_provider = (flags & HARDENED) ? keys_priv : keys_pub;

            // Evaluate the descriptor selected by `t` in position `i`.
            FlatSigningProvider script_provider, script_provider_cached;
            std::vector<CScript> spks, spks_cached;
            DescriptorCache desc_cache;
            BOOST_CHECK((t ? parse_priv : parse_pub)->Expand(i, key_provider, spks, script_provider, &desc_cache));

            // Compare the output with the expected result.
            BOOST_CHECK_EQUAL(spks.size(), ref.size());

            // Try to expand again using cached data, and compare.
            BOOST_CHECK(parse_pub->ExpandFromCache(i, desc_cache, spks_cached, script_provider_cached));
            BOOST_CHECK(spks == spks_cached);
            BOOST_CHECK(GetKeyData(script_provider, flags) == GetKeyData(script_provider_cached, flags));
            BOOST_CHECK(script_provider.scripts == script_provider_cached.scripts);
            BOOST_CHECK(GetKeyOriginData(script_provider, flags) == GetKeyOriginData(script_provider_cached, flags));

            // Check whether keys are in the cache
            const auto& der_xpub_cache = desc_cache.GetCachedDerivedExtPubKeys();
            const auto& parent_xpub_cache = desc_cache.GetCachedParentExtPubKeys();
            const size_t num_xpubs = CountExtPubs(pub1);
            if ((flags & RANGE) && !(flags & (DERIVE_HARDENED))) {
                // For ranged, unhardened derivation, None of the keys in origins should appear in the cache but the cache should have parent keys
                // But we can derive one level from each of those parent keys and find them all
                BOOST_CHECK(der_xpub_cache.empty());
                BOOST_CHECK(parent_xpub_cache.size() > 0);
                std::set<CPubKey> pubkeys;
                for (const auto& xpub_pair : parent_xpub_cache) {
                    const CExtPubKey& xpub = xpub_pair.second;
                    CExtPubKey der;
                    BOOST_CHECK(xpub.Derive(der, i));
                    pubkeys.insert(der.pubkey);
                }
                int count_pks = 0;
                for (const auto& origin_pair : script_provider_cached.origins) {
                    const CPubKey& pk = origin_pair.second.first;
                    count_pks += pubkeys.count(pk);
                }
                if (flags & MIXED_PUBKEYS) {
                    BOOST_CHECK_EQUAL(num_xpubs, count_pks);
                } else {
                    BOOST_CHECK_EQUAL(script_provider_cached.origins.size(), count_pks);
                }
            } else if (num_xpubs > 0) {
                // For ranged, hardened derivation, or not ranged, but has an xpub, all of the keys should appear in the cache
                BOOST_CHECK(der_xpub_cache.size() + parent_xpub_cache.size() == num_xpubs);
                if (!(flags & MIXED_PUBKEYS)) {
                    BOOST_CHECK(num_xpubs == script_provider_cached.origins.size());
                }
                // Get all of the derived pubkeys
                std::set<CPubKey> pubkeys;
                for (const auto& xpub_map_pair : der_xpub_cache) {
                    for (const auto& xpub_pair : xpub_map_pair.second) {
                        const CExtPubKey& xpub = xpub_pair.second;
                        pubkeys.insert(xpub.pubkey);
                    }
                }
                // Derive one level from all of the parents
                for (const auto& xpub_pair : parent_xpub_cache) {
                    const CExtPubKey& xpub = xpub_pair.second;
                    pubkeys.insert(xpub.pubkey);
                    CExtPubKey der;
                    BOOST_CHECK(xpub.Derive(der, i));
                    pubkeys.insert(der.pubkey);
                }
                int count_pks = 0;
                for (const auto& origin_pair : script_provider_cached.origins) {
                    const CPubKey& pk = origin_pair.second.first;
                    count_pks += pubkeys.count(pk);
                }
                if (flags & MIXED_PUBKEYS) {
                    BOOST_CHECK_EQUAL(num_xpubs, count_pks);
                } else {
                    BOOST_CHECK_EQUAL(script_provider_cached.origins.size(), count_pks);
                }
            } else if (!(flags & MIXED_PUBKEYS)) {
                // Only const pubkeys, nothing should be cached
                BOOST_CHECK(der_xpub_cache.empty());
                BOOST_CHECK(parent_xpub_cache.empty());
            }

            // Make sure we can expand using cached xpubs for unhardened derivation
            if (!(flags & DERIVE_HARDENED)) {
                // Evaluate the descriptor at i + 1
                FlatSigningProvider script_provider1, script_provider_cached1;
                std::vector<CScript> spks1, spk1_from_cache;
                BOOST_CHECK((t ? parse_priv : parse_pub)->Expand(i + 1, key_provider, spks1, script_provider1, nullptr));

                // Try again but use the cache from expanding i. That cache won't have the pubkeys for i + 1, but will have the parent xpub for derivation.
                BOOST_CHECK(parse_pub->ExpandFromCache(i + 1, desc_cache, spk1_from_cache, script_provider_cached1));
                BOOST_CHECK(spks1 == spk1_from_cache);
                BOOST_CHECK(GetKeyData(script_provider1, flags) == GetKeyData(script_provider_cached1, flags));
                BOOST_CHECK(script_provider1.scripts == script_provider_cached1.scripts);
                BOOST_CHECK(GetKeyOriginData(script_provider1, flags) == GetKeyOriginData(script_provider_cached1, flags));
            }

            // For each of the produced scripts, verify solvability, and when possible, try to sign a transaction spending it.
            for (size_t n = 0; n < spks.size(); ++n) {
                BOOST_CHECK_EQUAL(ref[n], HexStr(spks[n]));

                if (flags & (SIGNABLE | SIGNABLE_FAILS)) {
                    CMutableTransaction spend;
                    spend.nLockTime = spender_nlocktime;
                    spend.vin.resize(1);
                    spend.vin[0].nSequence = spender_nsequence;
                    spend.vout.resize(1);
                    std::vector<CTxOut> utxos(1);
                    PrecomputedTransactionData txdata;
                    txdata.Init(spend, std::move(utxos), /*force=*/true);
                    MutableTransactionSignatureCreator creator{spend, 0, CAmount{0}, &txdata, SIGHASH_DEFAULT};
                    SignatureData sigdata;
                    // We assume there is no collision between the hashes (eg h1=SHA256(SHA256(x)) and h2=SHA256(x))
                    sigdata.sha256_preimages = preimages;
                    sigdata.hash256_preimages = preimages;
                    sigdata.ripemd160_preimages = preimages;
                    sigdata.hash160_preimages = preimages;
                    const auto prod_sig_res = ProduceSignature(FlatSigningProvider{keys_priv}.Merge(FlatSigningProvider{script_provider}), creator, spks[n], sigdata);
                    BOOST_CHECK_MESSAGE(prod_sig_res == !(flags & SIGNABLE_FAILS), prv);
                }

                /* Infer a descriptor from the generated script, and verify its solvability and that it roundtrips. */
                auto inferred = InferDescriptor(spks[n], script_provider);
                BOOST_CHECK_EQUAL(inferred->IsSolvable(), !(flags & UNSOLVABLE));
                std::vector<CScript> spks_inferred;
                FlatSigningProvider provider_inferred;
                BOOST_CHECK(inferred->Expand(0, provider_inferred, spks_inferred, provider_inferred));
                BOOST_CHECK_EQUAL(spks_inferred.size(), 1U);
                BOOST_CHECK(spks_inferred[0] == spks[n]);
                BOOST_CHECK_EQUAL(InferDescriptor(spks_inferred[0], provider_inferred)->IsSolvable(), !(flags & UNSOLVABLE));
                BOOST_CHECK(GetKeyOriginData(provider_inferred, flags) == GetKeyOriginData(script_provider, flags));
            }

            // Test whether the observed key path is present in the 'paths' variable (which contains expected, unobserved paths),
            // and then remove it from that set.
            for (const auto& origin : script_provider.origins) {
                BOOST_CHECK_MESSAGE(paths.count(origin.second.second.path), "Unexpected key path: " + prv);
                left_paths.erase(origin.second.second.path);
            }
        }
    }

    // Verify no expected paths remain that were not observed.
    BOOST_CHECK_MESSAGE(left_paths.empty(), "Not all expected key paths found: " + prv);
}

void Check(const std::string& prv, const std::string& pub, const std::string& norm_pub, int flags,
           const std::vector<std::vector<std::string>>& scripts, const std::optional<OutputType>& type, std::optional<uint256> op_desc_id = std::nullopt,
           const std::set<std::vector<uint32_t>>& paths = ONLY_EMPTY, uint32_t spender_nlocktime=0,
           uint32_t spender_nsequence=CTxIn::SEQUENCE_FINAL, std::map<std::vector<uint8_t>, std::vector<uint8_t>> preimages={},
           std::optional<std::string> expected_prv = std::nullopt, std::optional<std::string> expected_pub = std::nullopt, int desc_index = 0)
{
    // Do not replace apostrophes with 'h' in prv and pub
    DoCheck(prv, pub, norm_pub, flags, scripts, type, op_desc_id, paths, /*replace_apostrophe_with_h_in_prv=*/false,
            /*replace_apostrophe_with_h_in_pub=*/false, /*spender_nlocktime=*/spender_nlocktime,
            /*spender_nsequence=*/spender_nsequence, /*preimages=*/preimages,
            expected_prv, expected_pub, desc_index);

    // Replace apostrophes with 'h' both in prv and in pub, if apostrophes are found in both
    if (prv.find('\'') != std::string::npos && pub.find('\'') != std::string::npos) {
        DoCheck(prv, pub, norm_pub, flags, scripts, type, op_desc_id, paths, /*replace_apostrophe_with_h_in_prv=*/true,
                /*replace_apostrophe_with_h_in_pub=*/true, /*spender_nlocktime=*/spender_nlocktime,
                /*spender_nsequence=*/spender_nsequence, /*preimages=*/preimages,
                expected_prv, expected_pub, desc_index);
    }
}

void CheckMultipath(const std::string& prv,
        const std::string& pub,
        const std::vector<std::string>& expanded_prvs,
        const std::vector<std::string>& expanded_pubs,
        const std::vector<std::string>& expanded_norm_pubs,
        int flags,
        const std::vector<std::vector<std::vector<std::string>>>& scripts,
        const std::optional<OutputType>& type,
        const std::vector<std::set<std::vector<uint32_t>>>& paths)
{
    assert(expanded_prvs.size() == expanded_pubs.size());
    assert(expanded_prvs.size() == expanded_norm_pubs.size());
    assert(expanded_prvs.size() == scripts.size());
    assert(expanded_prvs.size() == paths.size());
    for (size_t i = 0; i < expanded_prvs.size(); ++i) {
        Check(prv, pub, expanded_norm_pubs.at(i), flags, scripts.at(i), type, std::nullopt, paths.at(i),
              /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, /*preimages=*/{},
              expanded_prvs.at(i), expanded_pubs.at(i), i);
    }

    // The descriptor for each path must be standalone. They should not share common references. Test this
    // by parsing a multipath descriptor expression, deallocating all but one of the descriptors and making
    // sure we can perform operations on it.
    FlatSigningProvider prov, out;
    std::string error;
    const auto desc{[&](){
        auto parsed{Parse(pub, prov, error)};
        assert(parsed.size() > 1);
        return std::move(parsed.at(0));
    }()};
    desc->ToString();
    std::vector<CScript> out_scripts;
    desc->Expand(0, prov, out_scripts, out);
}

void CheckInferDescriptor(const std::string& script_hex, const std::string& expected_desc, const std::vector<std::string>& hex_scripts, const std::vector<std::pair<std::string, std::string>>& origin_pubkeys)
{
    std::vector<unsigned char> script_bytes{ParseHex(script_hex)};
    const CScript& script{script_bytes.begin(), script_bytes.end()};

    FlatSigningProvider provider;
    for (const std::string& prov_script_hex : hex_scripts) {
        std::vector<unsigned char> prov_script_bytes{ParseHex(prov_script_hex)};
        const CScript& prov_script{prov_script_bytes.begin(), prov_script_bytes.end()};
        provider.scripts.emplace(CScriptID(prov_script), prov_script);
    }
    for (const auto& [pubkey_hex, origin_str] : origin_pubkeys) {
        CPubKey origin_pubkey{ParseHex(pubkey_hex)};
        provider.pubkeys.emplace(origin_pubkey.GetID(), origin_pubkey);

        if (!origin_str.empty()) {
            KeyOriginInfo info;
            Span<const char> origin_sp{origin_str};
            std::vector<Span<const char>> origin_split = Split(origin_sp, "/");
            std::string fpr_str(origin_split[0].begin(), origin_split[0].end());
            auto fpr_bytes = ParseHex(fpr_str);
            std::copy(fpr_bytes.begin(), fpr_bytes.end(), info.fingerprint);
            for (size_t i = 1; i < origin_split.size(); ++i) {
                Span<const char> elem = origin_split[i];
                bool hardened = false;
                if (elem.size() > 0) {
                    const char last = elem[elem.size() - 1];
                    if (last == '\'' || last == 'h') {
                        elem = elem.first(elem.size() - 1);
                        hardened = true;
                    }
                }
                uint32_t p;
                assert(ParseUInt32(std::string(elem.begin(), elem.end()), &p));
                info.path.push_back(p | (((uint32_t)hardened) << 31));
            }

            provider.origins.emplace(origin_pubkey.GetID(), std::make_pair(origin_pubkey, info));
        }
    }

    std::string checksum{GetDescriptorChecksum(expected_desc)};

    std::unique_ptr<Descriptor> desc = InferDescriptor(script, provider);
    BOOST_CHECK_EQUAL(desc->ToString(), expected_desc + "#" + checksum);
}

}

BOOST_FIXTURE_TEST_SUITE(descriptor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(descriptor_test)
{
    // Basic single-key compressed
    Check("combo(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", SIGNABLE, {{"2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac","76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac","00149a1c78a507689f6f54b847ad1cef1e614ee23f1e","a91484ab21b1b2fd065d4504ff693d832434b6108d7b87"}}, std::nullopt, /*op_desc_id=*/uint256{"8ef71f7b6ac0918663f6706be469d6109f6922e21f484009d7ab49d77da36e8b"});
    Check("pk(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", SIGNABLE, {{"2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac"}}, std::nullopt, /*op_desc_id=*/uint256{"5fe175b43c58ac2cdde40521dc7d1dbc607f3dd795d00770206f4fdefb42229e"});
    Check("pkh([deadbeef/1/2'/3/4']RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "pkh([deadbeef/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "pkh([deadbeef/1/2h/3/4h]03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", SIGNABLE, {{"76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac"}}, OutputType::LEGACY, /*op_desc_id=*/uint256{"628130ae0530f2b24faf1ad2744a83568ac0ffac43e703e30c00d5f137869b84"}, {{1,0x80000002UL,3,0x80000004UL}});
    Check("wpkh(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", SIGNABLE, {{"00149a1c78a507689f6f54b847ad1cef1e614ee23f1e"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"4a47b7f497721bf3fc48c69a5d22bc1f3617238649a8ba7cb96fbd92fec84a7e"});
    Check("sh(wpkh(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN))", "sh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", "sh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", SIGNABLE, {{"a91484ab21b1b2fd065d4504ff693d832434b6108d7b87"}}, OutputType::P2SH_SEGWIT, /*op_desc_id=*/uint256{"a13112753066b5c59473a87c5771b1694a10531944a60e0ab2d7ad66ecb65bcd"});
    Check("tr(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", SIGNABLE | XONLY_KEYS, {{"512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11"}}, OutputType::BECH32M, /*op_desc_id=*/uint256{"4290f3d017b270be53b91abc56d9d2f23a3ff361d5b1d39550ba011e6cae0da5"});
    CheckUnparsable("sh(wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY2))", "sh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5))", "wpkh(): Pubkey '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5' is invalid"); // Invalid pubkey
    CheckUnparsable("pkh(deadbeef/1/2'/3/4']RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "pkh(deadbeef/1/2h/3/4h]03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "pkh(): Key origin start '[ character expected but not found, got 'd' instead"); // Missing start bracket in key origin
    CheckUnparsable("pkh([deadbeef]/1/2'/3/4']RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "pkh([deadbeef]/1/2'/3/4']03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "pkh(): Multiple ']' characters found for a single pubkey"); // Multiple end brackets in key origin

    // Basic single-key uncompressed
    Check("combo(6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9)", "combo(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "combo(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",SIGNABLE, {{"4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac","76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac"}}, std::nullopt, /*op_desc_id=*/uint256{"33f6bb5d32c04e9d9e5466a8212836743bd5466aa0b8d5331ce8aa0812371ffd"});
    Check("pk(6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9)", "pk(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "pk(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", SIGNABLE, {{"4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac"}}, std::nullopt, /*op_desc_id=*/uint256{"52306fc1f5d0cb78aacea9d3933092be9252adc27b146f97c16a94d6fcdb652e"});
    Check("pkh(6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9)", "pkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "pkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", SIGNABLE, {{"76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac"}}, OutputType::LEGACY, /*op_desc_id=*/uint256{"36657e8690d4015032da1a8c1e37b315c3f7ccb010e6ada12967878711962991"});
    CheckUnparsable("wpkh(6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9)", "wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "wpkh(): Uncompressed keys are not allowed"); // No uncompressed keys in witness
    CheckUnparsable("wsh(pk(6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9))", "wsh(pk(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235))", "pk(): Uncompressed keys are not allowed"); // No uncompressed keys in witness
    CheckUnparsable("sh(wpkh(6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9))", "sh(wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235))", "wpkh(): Uncompressed keys are not allowed"); // No uncompressed keys in witness

    // Equivalent single-key hybrid is not allowed
    CheckUnparsable("", "combo(07a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "combo(): Hybrid public keys are not allowed");
    CheckUnparsable("", "pk(0623542d61708e3fc48ba78fbe8fcc983ba94a520bc33f82b8e45e51dbc47af2726bcf181925eee1bdd868b109314f3ea92a6fc23d6b66057d3acfba04d6b08b58)", "pk(): Hybrid public keys are not allowed");
    CheckUnparsable("", "pkh(07a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "pkh(): Hybrid public keys are not allowed");

    // Some unconventional single-key constructions
    Check("sh(pk(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN))", "sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", "sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", SIGNABLE, {{"a9141857af51a5e516552b3086430fd8ce55f7c1a52487"}}, OutputType::LEGACY);
    Check("sh(pkh(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN))", "sh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", "sh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", SIGNABLE, {{"a9141a31ad23bf49c247dd531a623c2ef57da3c400c587"}}, OutputType::LEGACY);
    Check("wsh(pk(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN))", "wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", "wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", SIGNABLE, {{"00202e271faa2325c199d25d22e1ead982e45b64eeb4f31e73dbdf41bd4b5fec23fa"}}, OutputType::BECH32);
    Check("wsh(pkh(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN))", "wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", "wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", SIGNABLE, {{"0020338e023079b91c58571b20e602d7805fb808c22473cbc391a41b1bd3a192e75b"}}, OutputType::BECH32);
    Check("sh(wsh(pk(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)))", "sh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))", "sh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))", SIGNABLE, {{"a91472d0c5a3bfad8c3e7bd5303a72b94240e80b6f1787"}}, OutputType::P2SH_SEGWIT);
    Check("sh(wsh(pkh(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)))", "sh(wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))", "sh(wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))", SIGNABLE, {{"a914b61b92e2ca21bac1e72a3ab859a742982bea960a87"}}, OutputType::P2SH_SEGWIT);
    Check("tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5,{pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5),{pk(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)}})", "tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5,{pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5),{pk(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)}})", "tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5,{pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5),{pk(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)}})", XONLY_KEYS | SIGNABLE | MISSING_PRIVKEYS, {{"51201497ae16f30dacb88523ed9301bff17773b609e8a90518a3f96ea328a47d1500"}}, OutputType::BECH32M);

    // Versions with BIP32 derivations
    Check("combo([01234567]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)", "combo([01234567]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)", "combo([01234567]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)", SIGNABLE, {{"2102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0ac","76a91431a507b815593dfc51ffc7245ae7e5aee304246e88ac","001431a507b815593dfc51ffc7245ae7e5aee304246e","a9142aafb926eb247cb18240a7f4c07983ad1f37922687"}}, std::nullopt, /*op_desc_id=*/uint256{"4a3f2ef5436bdebf04fc3362d4593fa5e311897197794ea5e705cb063359ab74"});
    Check("pk(rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0)", "pk(rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0)", "pk(rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0)", DEFAULT, {{"210379e45b3cf75f9c5f9befd8e9506fb962f6a9d185ac87001ec44a8d3df8d4a9e3ac"}}, std::nullopt, /*op_desc_id=*/uint256{"949123cdb1ce78c2baf3d52f7b1a67a45bfd77405047de7cba665f9dbc360a1e"}, {{0}});
    Check("pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2147483647'/0)", "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2147483647'/0)", "pkh([bd16bee5/2147483647h]rpub4CHXR5bv6gEjx9FCLBAsGnRhKRXWLBGj97PirGaNcLcNHwBuuKtnS2FFeHiN5BxPhbJ9EpeNQSjrBYp6no9TQshDeZyPR7F9vYTedpTs13S/0)", HARDENED, {{"76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"}}, OutputType::LEGACY, /*op_desc_id=*/uint256{"1b7652614a1653ef7f5cf9f94ef2237d15ca6f8751eb64128eeed8a25b2c6067"}, {{0xFFFFFFFFUL,0}});

    Check("wpkh([ffffffff/13']rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/1/2/*)", "wpkh([ffffffff/13']rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*)", "wpkh([ffffffff/13h]rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*)", RANGE, {{"0014326b2249e3a25d5dc60935f044ee835d090ba859"},{"0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"},{"00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27"}}, OutputType::BECH32, /*op_desc_id=*/std::nullopt, {{0x8000000DUL, 1, 2, 0}, {0x8000000DUL, 1, 2, 1}, {0x8000000DUL, 1, 2, 2}});
    Check("sh(wpkh(rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/10/20/30/40/*'))", "sh(wpkh(rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*'))", "sh(wpkh(rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*h))", RANGE | HARDENED | DERIVE_HARDENED, {{"a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87"},{"a914bed59fc0024fae941d6e20a3b44a109ae740129287"},{"a9148483aa1116eb9c05c482a72bada4b1db24af654387"}}, OutputType::P2SH_SEGWIT, /*op_desc_id=*/std::nullopt, {{10, 20, 30, 40, 0x80000000UL}, {10, 20, 30, 40, 0x80000001UL}, {10, 20, 30, 40, 0x80000002UL}});
    Check("combo(rprv85JdpKAwUHJssKkUCmzkQmsJwb95Zpdhw4bR9iMJzzFf2GMFYLtDJ62s1ButNTUAfpQbQ8R78fjJL8AVbcQzaLxL1tHcoxNWZggzxfdcsbh/*)", "combo(rpub4JHzDphqJesB5opwJoXkmup3VcyZyHMZJHX1x6kvZKndu4gQ5tCTqtMLrUbDTj2EeidaucnZFb2uA1MjZEbwqFGWTbtmGqCi4ncTjFGsdRd/*)", "combo(rpub4JHzDphqJesB5opwJoXkmup3VcyZyHMZJHX1x6kvZKndu4gQ5tCTqtMLrUbDTj2EeidaucnZFb2uA1MjZEbwqFGWTbtmGqCi4ncTjFGsdRd/*)", RANGE, {{"2102df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076ac","76a914f90e3178ca25f2c808dc76624032d352fdbdfaf288ac","0014f90e3178ca25f2c808dc76624032d352fdbdfaf2","a91408f3ea8c68d4a7585bf9e8bda226723f70e445f087"},{"21032869a233c9adff9a994e4966e5b821fd5bac066da6c3112488dc52383b4a98ecac","76a914a8409d1b6dfb1ed2a3e8aa5e0ef2ff26b15b75b788ac","0014a8409d1b6dfb1ed2a3e8aa5e0ef2ff26b15b75b7","a91473e39884cb71ae4e5ac9739e9225026c99763e6687"}}, std::nullopt, /*op_desc_id=*/std::nullopt, {{0}, {1}});
    Check("tr(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/0/*,pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/1/*))", "tr(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/0/*,pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/*))", "tr(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/0/*,pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/*))", XONLY_KEYS | RANGE, {{"512078bc707124daa551b65af74de2ec128b7525e10f374dc67b64e00ce0ab8b3e12"}, {"512001f0a02a17808c20134b78faab80ef93ffba82261ccef0a2314f5d62b6438f11"}, {"512021024954fcec88237a9386fce80ef2ced5f1e91b422b26c59ccfc174c8d1ad25"}}, OutputType::BECH32M, /*op_desc_id=*/std::nullopt, {{0, 0}, {0, 1}, {0, 2}, {1, 0}, {1, 1}, {1, 2}});
    // Mixed xpubs and const pubkeys
    Check("wsh(multi(1,rprv85JdpKAwUHJssKkUCmzkQmsJwb95Zpdhw4bR9iMJzzFf2GMFYLtDJ62s1ButNTUAfpQbQ8R78fjJL8AVbcQzaLxL1tHcoxNWZggzxfdcsbh/0,RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN))","wsh(multi(1,rpub4JHzDphqJesB5opwJoXkmup3VcyZyHMZJHX1x6kvZKndu4gQ5tCTqtMLrUbDTj2EeidaucnZFb2uA1MjZEbwqFGWTbtmGqCi4ncTjFGsdRd/0,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))","wsh(multi(1,rpub4JHzDphqJesB5opwJoXkmup3VcyZyHMZJHX1x6kvZKndu4gQ5tCTqtMLrUbDTj2EeidaucnZFb2uA1MjZEbwqFGWTbtmGqCi4ncTjFGsdRd/0,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", MIXED_PUBKEYS, {{"0020cb155486048b23a6da976d4c6fe071a2dbc8a7b57aaf225b8955f2e2a27b5f00"}},OutputType::BECH32, /*op_desc_id=*/uint256{"d50560f505765988085ec13948a5b2306d573e4b80cb5560618f2c8ef5927263"},{{0},{}});
    // Mixed range xpubs and const pubkeys
    Check("multi(1,rprv85JdpKAwUHJssKkUCmzkQmsJwb95Zpdhw4bR9iMJzzFf2GMFYLtDJ62s1ButNTUAfpQbQ8R78fjJL8AVbcQzaLxL1tHcoxNWZggzxfdcsbh/*,RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)","multi(1,rpub4JHzDphqJesB5opwJoXkmup3VcyZyHMZJHX1x6kvZKndu4gQ5tCTqtMLrUbDTj2EeidaucnZFb2uA1MjZEbwqFGWTbtmGqCi4ncTjFGsdRd/*,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)","multi(1,rpub4JHzDphqJesB5opwJoXkmup3VcyZyHMZJHX1x6kvZKndu4gQ5tCTqtMLrUbDTj2EeidaucnZFb2uA1MjZEbwqFGWTbtmGqCi4ncTjFGsdRd/*,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", RANGE | MIXED_PUBKEYS, {{"512102df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e0762103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd52ae"},{"5121032869a233c9adff9a994e4966e5b821fd5bac066da6c3112488dc52383b4a98ec2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd52ae"},{"5121035d30b6c66dc1e036c45369da8287518cf7e0d6ed1e2b905171c605708f14ca032103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd52ae"}}, std::nullopt, /*op_desc_id=*/std::nullopt,{{2},{1},{0},{}});

    CheckUnparsable("combo([012345678]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)", "combo([012345678]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)", "combo(): Fingerprint is not 4 bytes (9 characters instead of 8 characters)"); // Too long key fingerprint
    CheckUnparsable("pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2147483648)", "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2147483648)", "pkh(): Key path value 2147483648 is out of range"); // BIP 32 path element overflow
    CheckUnparsable("pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/1aa)", "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/1aa)", "pkh(): Key path value '1aa' is not a valid uint32"); // Path is not valid uint
    Check("pkh([01234567/10/20]rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2147483647'/0)", "pkh([01234567/10/20]rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2147483647'/0)", "pkh([01234567/10/20/2147483647h]rpub4CHXR5bv6gEjx9FCLBAsGnRhKRXWLBGj97PirGaNcLcNHwBuuKtnS2FFeHiN5BxPhbJ9EpeNQSjrBYp6no9TQshDeZyPR7F9vYTedpTs13S/0)", HARDENED, {{"76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"}}, OutputType::LEGACY, /*op_desc_id=*/std::nullopt, {{10, 20, 0xFFFFFFFFUL, 0}});

    // Multipath versions with BIP32 derivations
    CheckMultipath("pk(rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/<0;1>)",
            "pk(rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/<0;1>)",
            {
                "pk(rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0)",
                "pk(rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/1)",
            },
            {
                "pk(rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0)",
                "pk(rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/1)",
            },
            {
                "pk(rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0)",
                "pk(rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/1)",
            },
            DEFAULT,
            {
                {{"210379e45b3cf75f9c5f9befd8e9506fb962f6a9d185ac87001ec44a8d3df8d4a9e3ac"}},
                {{"21034f8d02282ac6786737d0f37f0df7655f49daa24843bc7de3f4ea88603d26d10aac"}},
            },
            std::nullopt,
            {
                {{0}},
                {{1}},
            }
    );
    CheckMultipath("pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<2147483647h;0>/0)",
            "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<2147483647h;0>/0)",
            {
                "pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2147483647h/0)",
                "pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/0/0)",
            },
            {
                "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2147483647h/0)",
                "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/0/0)",
            },
            {
                "pkh([bd16bee5/2147483647h]rpub4CHXR5bv6gEjx9FCLBAsGnRhKRXWLBGj97PirGaNcLcNHwBuuKtnS2FFeHiN5BxPhbJ9EpeNQSjrBYp6no9TQshDeZyPR7F9vYTedpTs13S/0)",
                "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/0/0)",
            },
            HARDENED,
            {
                {{"76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"}},
                {{"76a914f103317b9f0b758a62cb3879281d23e3b1deb90d88ac"}},
            },
            OutputType::LEGACY,
            {
                {{0xFFFFFFFFUL,0}},
                {{0,0}},
            }
    );
    CheckMultipath("wpkh([ffffffff/13h]rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/<1;3>/2/*)",
            "wpkh([ffffffff/13h]rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/<1;3>/2/*)",
            {
                "wpkh([ffffffff/13h]rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/1/2/*)",
                "wpkh([ffffffff/13h]rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/3/2/*)",
            },
            {
                "wpkh([ffffffff/13h]rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*)",
                "wpkh([ffffffff/13h]rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/3/2/*)",
            },
            {
                "wpkh([ffffffff/13h]rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*)",
                "wpkh([ffffffff/13h]rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/3/2/*)",
            },
            RANGE,
            {
                {{"0014326b2249e3a25d5dc60935f044ee835d090ba859"},{"0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"},{"00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27"}},
                {{"001426183882ef9c76b9a44386e9b387f33cee7c3a2d"},{"001447c1b9dc215c3f8b47e572981eb97528768cde4e"},{"00146e92cbaa397f9caeccf9a049460258af6ccd67e2"}},
            },
            OutputType::BECH32,
            {
                {{0x8000000DUL, 1, 2, 0}, {0x8000000DUL, 1, 2, 1}, {0x8000000DUL, 1, 2, 2}},
                {{0x8000000DUL, 3, 2, 0}, {0x8000000DUL, 3, 2, 1}, {0x8000000DUL, 3, 2, 2}},
            }
    );
    CheckMultipath("sh(wpkh(rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/<10;100h>/20/30/40/*h))",
            "sh(wpkh(rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/<10;100h>/20/30/40/*h))",
            {
                "sh(wpkh(rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/10/20/30/40/*h))",
                "sh(wpkh(rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/100h/20/30/40/*h))",
            },
            {
                "sh(wpkh(rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*h))",
                "sh(wpkh(rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/100h/20/30/40/*h))",
            },
            {
                "sh(wpkh(rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*h))",
                "sh(wpkh(rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/100h/20/30/40/*h))",
            },
            RANGE | HARDENED | DERIVE_HARDENED,
            {
                {{"a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87"},{"a914bed59fc0024fae941d6e20a3b44a109ae740129287"},{"a9148483aa1116eb9c05c482a72bada4b1db24af654387"}},
                {{"a91470192039cb9529aadf4e53e46d9ac6a13790865787"},{"a914855859faffabf1e4ed2bb7411ab66f4599b1abd287"},{"a9148f2cfd4b486de247c44684160da164617ccf2c2687"}},
            },
            OutputType::P2SH_SEGWIT,
            {
                {{10, 20, 30, 40, 0x80000000UL}, {10, 20, 30, 40, 0x80000001UL}, {10, 20, 30, 40, 0x80000002UL}},
                {{0x80000064UL, 20, 30, 40, 0x80000000UL}, {0x80000064UL, 20, 30, 40, 0x80000001UL}, {0x80000064UL, 20, 30, 40, 0x80000002UL}},
            }
    );
    CheckMultipath("multi(2,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/<1;2>/*,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/<3;4>/0/*)",
            "multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/<1;2>/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/<3;4>/0/*)",
            {
                "multi(2,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/1/*,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/3/0/*)",
                "multi(2,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/2/*,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/4/0/*)",
            },
            {
                "multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/3/0/*)",
                "multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/2/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/4/0/*)",
            },
            {
                "multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/3/0/*)",
                "multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/2/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/4/0/*)",
            },
            RANGE,
            {
                {{"522103095e95d8c50ae3f3fea93fa8e983f710489f60ff681a658c06eba64622c824b121020443e9e729b42628913f1a69b46b7d43ff87c46e86140e12ee420d7e2e8caf8c52ae"},{"5221027512d6bd74e24eeb1ad752d5be800adc5886ded11c5293a9a701db83658b526a2102371e912dea5fefa56158908fe4c9f66bc925a8939b10f3821e8f8be797b9ca8252ae"},{"522102cc9fd211dc0a1c8bb7a106ff831be0e253bc992f21d08fb8a6fd43fae51b9b892103e43eddc68afc9746c9d09ce0bf8067b4f2416287abbc422ed1ac300673b1104952ae"}},
                {{"5221031c0517fff3d483f06ca769bd2326bf30aca1c4de278e676e6ef760c3301244c6210316e171ff4f82dc62ad3f0d84c97865034fc5041eaa508b48c1d7af77f301c8bd52ae"},{"52210240f010ccff4202ade2ef87756f6b9af57bbf5ebcb0393b949e6e5d45d30bff36210229057a7e03510b8cb66727fab3f47a52a02ea94eae03e7c2e81b72a26781bfde52ae"},{"5221034052522058a07b647bd08fa1a9eaedae0222eac76ddd122ff8096ec969398de721038cb8180dd4c956848bcf191e45aaf297146207559fb8737881156aadaf13704152ae"}},
            },
            std::nullopt,
            {
                {{1, 0}, {1, 1}, {1, 2}, {3, 0, 0}, {3, 0, 1}, {3, 0, 2}},
                {{2, 0}, {2, 1}, {2, 2}, {4, 0, 0}, {4, 0, 1}, {4, 0, 2}},
            }
    );
    CheckMultipath("pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<0;1;2>)",
            "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<0;1;2>)",
            {
                "pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/0)",
                "pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/1)",
                "pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2)",
            },
            {
                "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/0)",
                "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/1)",
                "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2)",
            },
            {
                "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/0)",
                "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/1)",
                "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2)",
            },
            DEFAULT,
            {
                {{"76a9145a61ff8eb7aaca3010db97ebda76121610b7809688ac"}},
                {{"76a9142f792a782cf4adbb321fe646c8e220563649b8fa88ac"}},
                {{"76a914dcc5b93b52177d78f97b3f2d259b9a86ee1403b188ac"}},
            },
            OutputType::LEGACY,
            {
                {{0}},
                {{1}},
                {{2}},
            }
    );
    CheckMultipath("sh(multi(2,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/<1;2;3>/0/*,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0/*,rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/<3;4;5>/*))",
            "sh(multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/<1;2;3>/0/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/*,rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/<3;4;5>/*))",
            {
                "sh(multi(2,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/1/0/*,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0/*,rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/3/*))",
                "sh(multi(2,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/2/0/*,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0/*,rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/4/*))",
                "sh(multi(2,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/3/0/*,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0/*,rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/5/*))",
            },
            {
                "sh(multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/0/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/*,rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/3/*))",
                "sh(multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/2/0/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/*,rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/4/*))",
                "sh(multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/3/0/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/*,rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/5/*))",
            },
            {
                "sh(multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/0/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/*,rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/3/*))",
                "sh(multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/2/0/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/*,rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/4/*))",
                "sh(multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/3/0/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/*,rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/5/*))",
            },
            RANGE,
            {
                {{"a914689cdf7de5836ec04fb971d128cc84858f73e11487"},{"a9142ea7dbaf0a77ee19f080cdacb3e13560e3cd9cf587"},{"a9143da854021f58f5e2d3ff6bb4fcd0ced877deb34987"}},
                {{"a9143dd613d162e89b83369bbf08e5f1977cfdc9b02787"},{"a91449eef5d3df5c465b20a630c66058fe689082d8e187"},{"a91492be56babf54ea2109c577f799ba6d73948e8c3287"}},
                {{"a9140093ca92097bdf557fbb0570bb77e1efd2e7529c87"},{"a914e4d0419d3d2ce8f921a800796811ff5462bb151887"},{"a914997bf69841ac444190dc02f5e6031dd6f8feab4587"}},
            },
            OutputType::LEGACY,
            {
                {{1, 0, 0}, {1, 0, 1}, {1, 0, 2}, {0, 0}, {0, 1}, {0, 2}, {0, 0, 3, 0}, {0, 0, 3, 1}, {0, 0, 3, 2}},
                {{2, 0, 0}, {2, 0, 1}, {2, 0, 2}, {0, 0}, {0, 1}, {0, 2}, {0, 0, 4, 0}, {0, 0, 4, 1}, {0, 0, 4, 2}},
                {{3, 0, 0}, {3, 0, 1}, {3, 0, 2}, {0, 0}, {0, 1}, {0, 2}, {0, 0, 5, 0}, {0, 0, 5, 1}, {0, 0, 5, 2}},
            }
    );
    CheckMultipath("tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/<6;7;8>/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/<1;2;3>/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/<3;4;5>/*)})",
            "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/<6;7;8>/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/<1;2;3>/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/<3;4;5>/*)})",
            {
                "tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/6/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/1/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/3/*)})",
                "tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/7/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/2/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/4/*)})",
                "tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/8/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/3/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/5/*)})",
            },
            {
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/3/*)})",
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/7/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/2/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/4/*)})",
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/8/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/3/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/5/*)})",
            },
            {
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/3/*)})",
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/7/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/2/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/4/*)})",
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/8/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/3/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/5/*)})",
            },
            XONLY_KEYS | RANGE,
            {
                {{"5120993e5b1d71d14cbb0a90c57ea0fed1d5bf77d5804cee206c3dbd7e4d2c67d869"},{"51207b8f629f6d406b92ffa6284f5545085eafb837c469018b715755f619b587163b"},{"512061f52925826e51e4615007557ddbea55b22c817909d7ebcfd3c454c634643ece"}},
                {{"5120633808b2156d0a6597e8b07f59c387bb4c2d5c02c4cb98f1802748e64c6abf5f"},{"5120fc5f06ded29328c170bf7e49e71c9cc8699befa2bf0a2a80802a1f32ab72d291"},{"5120fd05e2227e0dac972dff9941e332db8461bedc320c2a74def44e469ddbad9d21"}},
                {{"51205d19538c7c0901520eb712d079ae6eebed4f691021da466dc24e9575d9815ad0"},{"5120b9fc348ede2b7b9fb1f84c21741bb36bb3fa0905d0bc9417e07145d3142673f7"},{"51203a655bc5181b12efac82a5a5d1d0969b2ceb92c6fc37f505fdf00ee8afa09b33"}},
            },
            OutputType::BECH32M,
            {
                {{6, 0}, {6, 1}, {6, 2}, {1, 0, 0}, {1, 0, 1}, {1, 0, 2}, {0, 0, 3, 0}, {0, 0, 3, 1}, {0, 0, 3, 2}},
                {{7, 0}, {7, 1}, {7, 2}, {2, 0, 0}, {2, 0, 1}, {2, 0, 2}, {0, 0, 4, 0}, {0, 0, 4, 1}, {0, 0, 4, 2}},
                {{8, 0}, {8, 1}, {8, 2}, {3, 0, 0}, {3, 0, 1}, {3, 0, 2}, {0, 0, 5, 0}, {0, 0, 5, 1}, {0, 0, 5, 2}},
            }
    );
    CheckMultipath("tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/6/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/<1;2;3>/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/<3;4;5>/*)})",
            "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/<1;2;3>/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/<3;4;5>/*)})",
            {
                "tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/6/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/1/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/3/*)})",
                "tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/6/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/2/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/4/*)})",
                "tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/6/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/3/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/5/*)})",
            },
            {
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/3/*)})",
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/2/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/4/*)})",
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/3/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/5/*)})",
            },
            {
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/1/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/3/*)})",
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/2/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/4/*)})",
                "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/3/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/5/*)})",
            },
            XONLY_KEYS | RANGE,
            {
                {{"5120993e5b1d71d14cbb0a90c57ea0fed1d5bf77d5804cee206c3dbd7e4d2c67d869"},{"51207b8f629f6d406b92ffa6284f5545085eafb837c469018b715755f619b587163b"},{"512061f52925826e51e4615007557ddbea55b22c817909d7ebcfd3c454c634643ece"}},
                {{"5120c481a8ada38d1070094f62af526d4f8aae2eb1e44d1fd961be6a25198b4da77b"},{"512034a2d31c091905e62def62b575b88beff41723d83acb02dfada2e73d9c529b40"},{"5120e0ecc278655b092962ded92a5781bd8e86e8408055de05f121e107fa211e5dfb"}},
                {{"51206052cff5efc848e4b38a947803943eb1eb0076523eec1041969851ebcd265555"},{"512009ed83d758c0bdd36e225c961810761c7a360533434a41a17bba709e331e6cd1"},{"5120fcd77851ebaac37564b87e9b351c54492a8fbb1d6afdf7f3a9317703a002b22b"}},
            },
            OutputType::BECH32M,
            {
                {{6, 0}, {6, 1}, {6, 2}, {1, 0, 0}, {1, 0, 1}, {1, 0, 2}, {0, 0, 3, 0}, {0, 0, 3, 1}, {0, 0, 3, 2}},
                {{6, 0}, {6, 1}, {6, 2}, {2, 0, 0}, {2, 0, 1}, {2, 0, 2}, {0, 0, 4, 0}, {0, 0, 4, 1}, {0, 0, 4, 2}},
                {{6, 0}, {6, 1}, {6, 2}, {3, 0, 0}, {3, 0, 1}, {3, 0, 2}, {0, 0, 5, 0}, {0, 0, 5, 1}, {0, 0, 5, 2}},
            }
    );
    CheckMultipath("wsh(or_d(pk([2557c640/48h/1h/0h/2h]rprv7zsXsGDuVVxoUKG9EJsW6ahpaJtKRkRooSBvPPNuRwHus1GzetRyjq34GpYq2LQv75a8kt6jhx3wMfAyjpJVUDVUuhEFtf5E7uQkijjJes6/<0;1>/*),and_v(v:pkh([00aabb22/48h/1h/0h/2h]rprv7zsXsGDuVVxoVRmfcPmv27hJ6fakc3DiJPaqqCHgmw9CzAQXoLNn4yaNntFMKLChB1E1UB9YvHNsPVx6ALcmJ5EmJiEvKVasmwiMGW71eTR/<0;1>/*),older(2))))",
            "wsh(or_d(pk([2557c640/48h/1h/0h/2h]rpub4DrtGmkoKsX6goLcLLQWTieZ8LioqD9fAf7XBmnWzGptjoc9CRkEHdMY8611PHkvgXVeGxgTgU4ZEYD7uzMBwSWEF27U5xLttcnvDEdaiUf/<0;1>/*),and_v(v:pkh([00aabb22/48h/1h/0h/2h]rpub4DrtGmkoKsX6hur8iRJvPFe2ehRF1VwZfcWSdahJLGgBrxjgLsh2cmtre9RG2Kuvb8zHX4LuWqa4SxNH4AKSnagWfPcX4Yc7hRpJAL5B8mJ/<0;1>/*),older(2))))",
            {
                "wsh(or_d(pk([2557c640/48h/1h/0h/2h]rprv7zsXsGDuVVxoUKG9EJsW6ahpaJtKRkRooSBvPPNuRwHus1GzetRyjq34GpYq2LQv75a8kt6jhx3wMfAyjpJVUDVUuhEFtf5E7uQkijjJes6/0/*),and_v(v:pkh([00aabb22/48h/1h/0h/2h]rprv7zsXsGDuVVxoVRmfcPmv27hJ6fakc3DiJPaqqCHgmw9CzAQXoLNn4yaNntFMKLChB1E1UB9YvHNsPVx6ALcmJ5EmJiEvKVasmwiMGW71eTR/0/*),older(2))))",
                "wsh(or_d(pk([2557c640/48h/1h/0h/2h]rprv7zsXsGDuVVxoUKG9EJsW6ahpaJtKRkRooSBvPPNuRwHus1GzetRyjq34GpYq2LQv75a8kt6jhx3wMfAyjpJVUDVUuhEFtf5E7uQkijjJes6/1/*),and_v(v:pkh([00aabb22/48h/1h/0h/2h]rprv7zsXsGDuVVxoVRmfcPmv27hJ6fakc3DiJPaqqCHgmw9CzAQXoLNn4yaNntFMKLChB1E1UB9YvHNsPVx6ALcmJ5EmJiEvKVasmwiMGW71eTR/1/*),older(2))))",
            },
            {
                "wsh(or_d(pk([2557c640/48h/1h/0h/2h]rpub4DrtGmkoKsX6goLcLLQWTieZ8LioqD9fAf7XBmnWzGptjoc9CRkEHdMY8611PHkvgXVeGxgTgU4ZEYD7uzMBwSWEF27U5xLttcnvDEdaiUf/0/*),and_v(v:pkh([00aabb22/48h/1h/0h/2h]rpub4DrtGmkoKsX6hur8iRJvPFe2ehRF1VwZfcWSdahJLGgBrxjgLsh2cmtre9RG2Kuvb8zHX4LuWqa4SxNH4AKSnagWfPcX4Yc7hRpJAL5B8mJ/0/*),older(2))))",
                "wsh(or_d(pk([2557c640/48h/1h/0h/2h]rpub4DrtGmkoKsX6goLcLLQWTieZ8LioqD9fAf7XBmnWzGptjoc9CRkEHdMY8611PHkvgXVeGxgTgU4ZEYD7uzMBwSWEF27U5xLttcnvDEdaiUf/1/*),and_v(v:pkh([00aabb22/48h/1h/0h/2h]rpub4DrtGmkoKsX6hur8iRJvPFe2ehRF1VwZfcWSdahJLGgBrxjgLsh2cmtre9RG2Kuvb8zHX4LuWqa4SxNH4AKSnagWfPcX4Yc7hRpJAL5B8mJ/1/*),older(2))))"
            },
            {
                "wsh(or_d(pk([2557c640/48h/1h/0h/2h]rpub4DrtGmkoKsX6goLcLLQWTieZ8LioqD9fAf7XBmnWzGptjoc9CRkEHdMY8611PHkvgXVeGxgTgU4ZEYD7uzMBwSWEF27U5xLttcnvDEdaiUf/0/*),and_v(v:pkh([00aabb22/48h/1h/0h/2h]rpub4DrtGmkoKsX6hur8iRJvPFe2ehRF1VwZfcWSdahJLGgBrxjgLsh2cmtre9RG2Kuvb8zHX4LuWqa4SxNH4AKSnagWfPcX4Yc7hRpJAL5B8mJ/0/*),older(2))))",
                "wsh(or_d(pk([2557c640/48h/1h/0h/2h]rpub4DrtGmkoKsX6goLcLLQWTieZ8LioqD9fAf7XBmnWzGptjoc9CRkEHdMY8611PHkvgXVeGxgTgU4ZEYD7uzMBwSWEF27U5xLttcnvDEdaiUf/1/*),and_v(v:pkh([00aabb22/48h/1h/0h/2h]rpub4DrtGmkoKsX6hur8iRJvPFe2ehRF1VwZfcWSdahJLGgBrxjgLsh2cmtre9RG2Kuvb8zHX4LuWqa4SxNH4AKSnagWfPcX4Yc7hRpJAL5B8mJ/1/*),older(2))))"
            },
            RANGE,
            {
                {{"0020538436a60f2a638ea9e1e1342e9b93374aa7ec559ff0a805b3a185d4ba855d7f"},{"00203a588d107d604b6913201c7c1e1722f07a0f8fb3a382744f17b9ae5f6ccfcdd7"},{"0020d30fb375f7c491a208e77c7b5d0996ca14cf4a770c2ab5981f915c0e4565c74a"}},
                {{"002072b5fc3a691c48fdbaf485f27e787b4094055d4b434c90c81ed1090f3d48733b"},{"0020a9ccdf4496e5d60db4704b27494d9d74f54a16c180ff954a43ce5e3aa465113a"},{"0020d17e21820a0069ca87049513eca763f08a74b586724441e7d76fc5142bcc327c"}},
            },
            OutputType::BECH32,
            {
                {{0x80000000UL + 48, 0x80000000UL + 1, 0x80000000UL, 0x80000000UL + 2, 0, 0}, {0x80000000UL + 48, 0x80000000UL + 1, 0x80000000UL, 0x80000000UL + 2, 0, 1}, {0x80000000UL + 48, 0x80000000UL + 1, 0x80000000UL, 0x80000000UL + 2, 0, 2}},
                {{0x80000000UL + 48, 0x80000000UL + 1, 0x80000000UL, 0x80000000UL + 2, 1, 0}, {0x80000000UL + 48, 0x80000000UL + 1, 0x80000000UL, 0x80000000UL + 2, 1, 1}, {0x80000000UL + 48, 0x80000000UL + 1, 0x80000000UL, 0x80000000UL + 2, 1, 2}},
            }
    );
    CheckMultipath("tr(rprv82Z6p4MwAyGsSfzciBwTBR37Gr3JUVxdTj9aCsHJ2XHQzmqU5SyAZ5TAQf8EnYafPo8uvJhWvjFUGGhVMHYs6UUZqVYftnUzSjji4yR4eUf,l:pk(rprv84AduaLdNx2PgnJ4sumVs24VmgH7j7BkDAabAbWYGwLtqeRhZ8crURdhtnZzteFvyXe5Rx29KXH9wQU13sE5Ghyixdw7K85jJ3brsBCRmM4/<2;3>))",
        "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF/<2;3>))",
        {
            "tr(rprv82Z6p4MwAyGsSfzciBwTBR37Gr3JUVxdTj9aCsHJ2XHQzmqU5SyAZ5TAQf8EnYafPo8uvJhWvjFUGGhVMHYs6UUZqVYftnUzSjji4yR4eUf,l:pk(rprv84AduaLdNx2PgnJ4sumVs24VmgH7j7BkDAabAbWYGwLtqeRhZ8crURdhtnZzteFvyXe5Rx29KXH9wQU13sE5Ghyixdw7K85jJ3brsBCRmM4/2))",
            "tr(rprv82Z6p4MwAyGsSfzciBwTBR37Gr3JUVxdTj9aCsHJ2XHQzmqU5SyAZ5TAQf8EnYafPo8uvJhWvjFUGGhVMHYs6UUZqVYftnUzSjji4yR4eUf,l:pk(rprv84AduaLdNx2PgnJ4sumVs24VmgH7j7BkDAabAbWYGwLtqeRhZ8crURdhtnZzteFvyXe5Rx29KXH9wQU13sE5Ghyixdw7K85jJ3brsBCRmM4/3))",
        },
        {
            "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF/2))",
            "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF/3))",
        },
        {
            "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF/2))",
            "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF/3))",
        },
        XONLY_KEYS,
        {
            {{"512094cb097990da64eebbad7b979b1326f3cbe356357abf4deb4c4ff80c7acbe902"}},
            {{"5120f091450b88c606f5cbc3f0cebe89e00bc5dd27f92e22f54da06439bc0c401f41"}},
        },
        OutputType::BECH32M,
        {
            {{2}, {}},
            {{3}, {}},
        }
    );
    CheckMultipath("tr(rprv82Z6p4MwAyGsSfzciBwTBR37Gr3JUVxdTj9aCsHJ2XHQzmqU5SyAZ5TAQf8EnYafPo8uvJhWvjFUGGhVMHYs6UUZqVYftnUzSjji4yR4eUf/<2;3>,l:pk(rprv84AduaLdNx2PgnJ4sumVs24VmgH7j7BkDAabAbWYGwLtqeRhZ8crURdhtnZzteFvyXe5Rx29KXH9wQU13sE5Ghyixdw7K85jJ3brsBCRmM4))",
            "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV/<2;3>,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF))",
            {
                "tr(rprv82Z6p4MwAyGsSfzciBwTBR37Gr3JUVxdTj9aCsHJ2XHQzmqU5SyAZ5TAQf8EnYafPo8uvJhWvjFUGGhVMHYs6UUZqVYftnUzSjji4yR4eUf/2,l:pk(rprv84AduaLdNx2PgnJ4sumVs24VmgH7j7BkDAabAbWYGwLtqeRhZ8crURdhtnZzteFvyXe5Rx29KXH9wQU13sE5Ghyixdw7K85jJ3brsBCRmM4))",
                "tr(rprv82Z6p4MwAyGsSfzciBwTBR37Gr3JUVxdTj9aCsHJ2XHQzmqU5SyAZ5TAQf8EnYafPo8uvJhWvjFUGGhVMHYs6UUZqVYftnUzSjji4yR4eUf/3,l:pk(rprv84AduaLdNx2PgnJ4sumVs24VmgH7j7BkDAabAbWYGwLtqeRhZ8crURdhtnZzteFvyXe5Rx29KXH9wQU13sE5Ghyixdw7K85jJ3brsBCRmM4))",
            },
            {
                "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV/2,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF))",
                "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV/3,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF))",
            },
            {
                "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV/2,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF))",
                "tr(rpub4FYTDZtq1LqAfA55pDUTYYyqpssnsxgUpx5B1FguarpPsaAcczHR6smeFuP3adu1zhYEpvLpXVQk7rSrr7nbua68hFFYe45SWLVk4RW6aZV/3,l:pk(rpub4H9zK5sXDKaguGNXywJWEA1EKi7c8ZubaPWBxyv9qGssiSkr6fw72DxBk3oHCXMeETvaYAXVkserWYtJF7VvoF8DeTu8mUX9489G6JJGMkF))",
            },
            XONLY_KEYS,
            {
                {{"51200e3c14456bfa30f9f0bed6e55f35e1e9ca17c835e9f71b25bac0dfaab38ff2cd"}},
                {{"51202bdda29337ecaf8fcd5aa395febac6f99b8a866a0e8fb3f7bde2e24b1a7df2ba"}},
            },
            OutputType::BECH32M,
            {
                {{2}, {}},
                {{3}, {}},
            }
    );
    CheckUnparsable("pkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<0;1>/<2;3>)", "pkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<0;1>/<2;3>)", "pkh(): Multiple multipath key path specifiers found");
    CheckUnparsable("pkh([deadbeef/<0;1>]rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/0)", "pkh([deadbeef/<0;1>]rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/0)", "pkh(): Key path value \'<0;1>\' specifies multipath in a section where multipath is not allowed");
    CheckUnparsable("tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/6/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/<1;2;3>/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/<3;4>/*)})", "tr(rpub4E5HcbMMERzfS4gcAxfuE8CpeRhpEUPkBwx1xf8Eccj9yD6pbifqC7RNrfPwDENGSahoDvA8HvAJf3hHVSUp8H1GNLi1jUE64P9U6BfWvH1/6/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/<1;2;3>/0/*),pk(rpub4DhfsZGoNntf5MZR5Gx73cAS1e9ZbMHfEY5D9AJSjAuLfeMAEo8uUfFhLSGwmsRcVctcHbMhBRYn1CHxQhzn31g9Xjqdu54eAUw5fc3qpJE/0/0/<3;4>/*)})", "tr(): Multipath subscripts have mismatched lengths");
    CheckUnparsable("tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/<6;7;8;9>/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/<1;2;3>/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/<3;4;5>/*)})", "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/<6;7;8;9>/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/<1;2;3>/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/<3;4;5>/*)})", "tr(): Multipath subscripts have mismatched lengths");
    CheckUnparsable("tr(rprv7v2RjrNn6xnRvnkKkJmaMt98kWpz2aXm4A8nMaAZ1sRt9A8aEw7Nt4cpLJVR2wQbK1s3oxEsnFntKpqErQDxzdMuGR1x9q1TfV5fySpmWfP/<6;7>/*,{pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/<1;2;3>/0/*),pk(rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/<3;4;5>/*)})", "tr(rpub491n9MufwLLj9GpnrLJaj25sJYfUS3FcRP4P9xaAaCxs1xTinURdRrwJBbJy4kCpW3kv9ExsUf5GXxrRou4LxcdVrCUkpEj7ndDXpLxb7qX/<6;7>/*,{pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/<1;2;3>/0/*),pk(rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/<3;4;5>/*)})", "tr(): Multipath internal key mismatches multipath subscripts lengths");
    CheckUnparsable("sh(multi(2,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/<1;2;3>/0/*,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0/*,rprv7v2RjrNn6xnRwxLEN9669rHsxVud8E7ZR9143zyKDMwhSwi25MYQfKzvYDvSaDuNB2M1qJp7mTurVVfJYBqKVXVffCaknfGYR5cYaVbfiAy/0/0/<3;4>/*))", "sh(multi(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/<1;2;3>/0/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/*,rpub491n9MufwLLjASQhUAd6WzEcWXk7XgqQnMverPNvmhUgKk3ActrfD8KQPWxoG8etDTVyDBiHUruvJMYSaV78CK7RvdC9wNyPyf6REtE1gyq/0/0/<3;4>/*))", "multi(): Multipath derivation paths have mismatched lengths");
    CheckUnparsable("wpkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<0>/*)", "wpkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<0>/*)", "wpkh(): Multipath key path specifiers must have at least two items");
    CheckUnparsable("wsh(andor(pk(rprv81Gg6hV57EYj2rcwE7MZGy6LYZK555bt7a9T5kcdrWXQvofHTgGJBG1oCCEu6NCPZv1ydEELR8XB6siRrUA4pqUHwJwXkgc9Ba1WjR7nHZg/0'/<0;1;2;3>/*),older(10000),pk(rprv81A1ks5dXTgviqVpTJAhtPetRv2R2Hx9WeyYZfrP1cwwCiWV2gcusqxPopYQ2Jp2jfcy4wEEiKjLVYGo5Hs6fwmJGpwkSXRCebtHoaFG6TL/8/<0;1;2>/*)))", "wsh(andor(pk(rpub4EG2WD1xwc72FLhQL8tZe7356b9ZUYKjUo53t92FQr4PobzS1DaYj4LH3TpgQLzPD737VJTKqCdifPEBuBtsnhDEFg9Zb9ioB6hzdE6uo5M/0'/<0;1;2;3>/*),older(10000),pk(rpub4E9NANcXMqFDwKaHZKhiFXbcywruRkfzssu9N4FzZxUv5WqdaDwAReGsf6NobdL84KrTZBoRWRWSWvkwbzAGM8Aydf2TJkC8R8YE6eE6xBn/8/<0;1;2>/*)))", "Miniscript: Multipath derivation paths have mismatched lengths");
    CheckUnparsable("wpkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<>/*)", "wpkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<>/*)", "wpkh(): Multipath key path specifiers must have at least two items");
    CheckUnparsable("wpkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<0/*)", "wpkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<0/*)", "wpkh(): Key path value '<0' is not a valid uint32");
    CheckUnparsable("wpkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/0>/*)", "wpkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/0>/*)", "wpkh(): Key path value '0>' is not a valid uint32");
    CheckUnparsable("wpkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<0;>/*)", "wpkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<0;>/*)", "wpkh(): Key path value '' is not a valid uint32");
    CheckUnparsable("wpkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<;1>/*)", "wpkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<;1>/*)", "wpkh(): Key path value '' is not a valid uint32");
    CheckUnparsable("wpkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<0;1;>/*)", "wpkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<0;1;>/*)", "wpkh(): Key path value '' is not a valid uint32");
    CheckUnparsable("wpkh(rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/<1;1>/*)", "wpkh(rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/<1;1>/*)", "wpkh(): Duplicated key path value 1 in multipath specifier");

    // Multisig constructions
    Check("multi(1,RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN,6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9)", "multi(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "multi(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", SIGNABLE, {{"512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae"}}, std::nullopt, /*op_desc_id=*/uint256{"b147e25eb4a9d3da4e86ed8e970d817563ae2cb9c71a756b11cfdeb4dc11b70c"});
    Check("sortedmulti(1,RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN,6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9)", "sortedmulti(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "sortedmulti(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", SIGNABLE, {{"512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae"}}, std::nullopt, /*op_desc_id=*/uint256{"62b59d1e32a62176ef7a17538f3b80c7d1afc53e5644eb753525bdb5d556486c"});
    Check("sortedmulti(1,6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9,RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "sortedmulti(1,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "sortedmulti(1,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", SIGNABLE, {{"512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae"}}, std::nullopt);
    Check("sh(multi(2,[00000000/111'/222]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0))", "sh(multi(2,[00000000/111'/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))", "sh(multi(2,[00000000/111h/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))", DEFAULT, {{"a91445a9a622a8b0a1269944be477640eedc447bbd8487"}}, OutputType::LEGACY, /*op_desc_id=*/std::nullopt, {{0x8000006FUL,222},{0}});
    Check("sortedmulti(2,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/*,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0/0/*)", "sortedmulti(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/0/*)", "sortedmulti(2,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE/*,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0/0/*)", RANGE, {{"5221025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b62102fbd47cc8034098f0e6a94c6aeee8528abf0a2153a5d8e46d325b7284c046784652ae"}, {"52210264fd4d1f5dea8ded94c61e9641309349b62f27fbffe807291f664e286bfbe6472103f4ece6dfccfa37b211eb3d0af4d0c61dba9ef698622dc17eecdf764beeb005a652ae"}, {"5221022ccabda84c30bad578b13c89eb3b9544ce149787e5b538175b1d1ba259cbb83321024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c52ae"}}, std::nullopt, /*op_desc_id=*/std::nullopt, {{0}, {1}, {2}, {0, 0, 0}, {0, 0, 1}, {0, 0, 2}});
    Check("wsh(multi(2,rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2147483647'/0,rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/1/2/*,rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/10/20/30/40/*'))", "wsh(multi(2,rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2147483647'/0,rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*,rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*'))", "wsh(multi(2,[bd16bee5/2147483647h]rpub4CHXR5bv6gEjx9FCLBAsGnRhKRXWLBGj97PirGaNcLcNHwBuuKtnS2FFeHiN5BxPhbJ9EpeNQSjrBYp6no9TQshDeZyPR7F9vYTedpTs13S/0,rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*,rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*h))", HARDENED | RANGE | DERIVE_HARDENED, {{"0020b92623201f3bb7c3771d45b2ad1d0351ea8fbf8cfe0a0e570264e1075fa1948f"},{"002036a08bbe4923af41cf4316817c93b8d37e2f635dd25cfff06bd50df6ae7ea203"},{"0020a96e7ab4607ca6b261bfe3245ffda9c746b28d3f59e83d34820ec0e2b36c139c"}}, OutputType::BECH32, /*op_desc_id=*/std::nullopt, {{0xFFFFFFFFUL,0}, {1,2,0}, {1,2,1}, {1,2,2}, {10, 20, 30, 40, 0x80000000UL}, {10, 20, 30, 40, 0x80000001UL}, {10, 20, 30, 40, 0x80000002UL}});
    Check("sh(wsh(multi(16,RB6Ezip4uy3ERmQw269etHFMXa9JHgB1dRAYL1G6Q6fphSQTXooR,R7ZSzk9gKnxN2NTFFW1M59CNAXf1QFHoYoGSKk9gjEZrSQDhk5RC,R96kZMKroL2iz4PQqjuu84dev2nwrCbuXkJQVdQUgE7DpZjiMM8g,RCUYPHWwaMdkfrQFedbfKLK7V84kCfrsXYaeTSdmmodfcMrYeUYQ,RC6pJutkuPp4qjzAgcLzoaowUQPFEweX7LPsnLwkmroZGKe1twae,R8WGP63wETM4VgxxkyeF9yV2HQS2LTdwVW47FcADFNu7sWgZTMTm,RFwhRNsNv8gUBayMnRujn17JZndWS3xjLASsntrFYoQVCXKMH6k9,RAYCV9s6MaAzeaJ1dSqDMp5QTRoobBzDDwsx51ZDQTzq2PZWu1FZ,RE5MVFQoPQzsbYky6CNL4GfBq1g9KCPmd8NXSYnwdSc7UKFYMedT,RA2Mogi7e8cWpsner9afKvMiwdwt3SKbmR3mQpbzn1bDSD48gJuG,R8AjyvvubqdCX1SkimAJkeNKEfpk2ZZy89YBpveWSt3V1yjwFvvV,RAVYbvJrGiNWjkiYgoofYYcQT3zTPxj6St586vC1iP47DniF32Ar,RAytMqZRzbQkrgexqWaSYHrctR4LuCbptG577KFdds471jSnMDU1,R9UbU3aYaVc5AwcmxpAJCrEi92ErCEmod56bEbhpiKpkVrUCR4u4,RAbHeoLRRoThRVV8Npccy5Vjhe9jwYfPPy1DrXVxj3RJ3bHcAjnW,RCFfJWaTvEu9RsGRxif9fVhzp7zv4C1rn2275SJkcWaPwQiMB123)))","sh(wsh(multi(16,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232)))", "sh(wsh(multi(16,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232)))", SIGNABLE, {{"a9147fc63e13dc25e8a95a3cee3d9a714ac3afd96f1e87"}}, OutputType::P2SH_SEGWIT, /*op_desc_id=*/std::nullopt);
    Check("tr(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN,pk(RB6Ezip4uy3ERmQw269etHFMXa9JHgB1dRAYL1G6Q6fphSQTXooR))", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))", SIGNABLE | XONLY_KEYS, {{"512017cf18db381d836d8923b1bdb246cfcd818da1a9f0e6e7907f187f0b2f937754"}}, OutputType::BECH32M, /*op_desc_id=*/uint256{"af482b44c10b737b678e1091584818372e169e2dc5219e2877fabe1b83ae467b"});
    Check("tr(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN,multi_a(1,RB6Ezip4uy3ERmQw269etHFMXa9JHgB1dRAYL1G6Q6fphSQTXooR))", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,multi_a(1,669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,multi_a(1,669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))", SIGNABLE | XONLY_KEYS, {{"5120eb5bd3894327d75093891cc3a62506df7d58ec137fcd104cdd285d67816074f3"}}, OutputType::BECH32M);
    CheckUnparsable("sh(multi(16,RB6Ezip4uy3ERmQw269etHFMXa9JHgB1dRAYL1G6Q6fphSQTXooR,R7ZSzk9gKnxN2NTFFW1M59CNAXf1QFHoYoGSKk9gjEZrSQDhk5RC,R96kZMKroL2iz4PQqjuu84dev2nwrCbuXkJQVdQUgE7DpZjiMM8g,RCUYPHWwaMdkfrQFedbfKLK7V84kCfrsXYaeTSdmmodfcMrYeUYQ,RC6pJutkuPp4qjzAgcLzoaowUQPFEweX7LPsnLwkmroZGKe1twae,R8WGP63wETM4VgxxkyeF9yV2HQS2LTdwVW47FcADFNu7sWgZTMTm,RFwhRNsNv8gUBayMnRujn17JZndWS3xjLASsntrFYoQVCXKMH6k9,RAYCV9s6MaAzeaJ1dSqDMp5QTRoobBzDDwsx51ZDQTzq2PZWu1FZ,RE5MVFQoPQzsbYky6CNL4GfBq1g9KCPmd8NXSYnwdSc7UKFYMedT,RA2Mogi7e8cWpsner9afKvMiwdwt3SKbmR3mQpbzn1bDSD48gJuG,R8AjyvvubqdCX1SkimAJkeNKEfpk2ZZy89YBpveWSt3V1yjwFvvV,RAVYbvJrGiNWjkiYgoofYYcQT3zTPxj6St586vC1iP47DniF32Ar,RAytMqZRzbQkrgexqWaSYHrctR4LuCbptG577KFdds471jSnMDU1,R9UbU3aYaVc5AwcmxpAJCrEi92ErCEmod56bEbhpiKpkVrUCR4u4,RAbHeoLRRoThRVV8Npccy5Vjhe9jwYfPPy1DrXVxj3RJ3bHcAjnW,RCFfJWaTvEu9RsGRxif9fVhzp7zv4C1rn2275SJkcWaPwQiMB123))","sh(multi(16,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232))", "P2SH script is too large, 547 bytes is larger than 520 bytes"); // P2SH does not fit 16 compressed pubkeys in a redeemscript
    CheckUnparsable("wsh(multi(2,[aaaaaaaa][aaaaaaaa]rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2147483647'/0,rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/1/2/*,rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaaa][aaaaaaaa]rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2147483647h/0,rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*,rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*h))", "Multi: Multiple ']' characters found for a single pubkey"); // Double key origin descriptor
    CheckUnparsable("wsh(multi(2,[aaaagaaa]rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2147483647'/0,rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/1/2/*,rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/10/20/30/40/*'))", "wsh(multi(2,[aaagaaaa]rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2147483647h/0,rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*,rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*h))", "Multi: Fingerprint 'aaagaaaa' is not hex"); // Non hex fingerprint
    CheckUnparsable("wsh(multi(2,[aaaaaaaa],rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/1/2/*,rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaaa],rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*,rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*h))", "Multi: No key provided"); // No public key with origin
    CheckUnparsable("wsh(multi(2,[aaaaaaa]rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2147483647'/0,rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/1/2/*,rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaa]rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2147483647h/0,rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*,rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*h))", "Multi: Fingerprint is not 4 bytes (7 characters instead of 8 characters)"); // Too short fingerprint
    CheckUnparsable("wsh(multi(2,[aaaaaaaaa]rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS/2147483647'/0,rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/1/2/*,rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaaaa]rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE/2147483647h/0,rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/1/2/*,rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN/10/20/30/40/*h))", "Multi: Fingerprint is not 4 bytes (9 characters instead of 8 characters)"); // Too long fingerprint
    CheckUnparsable("multi(a,RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN,6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9)", "multi(a,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "Multi threshold 'a' is not valid"); // Invalid threshold
    CheckUnparsable("multi(0,RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN,6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9)", "multi(0,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "Multisig threshold cannot be 0, must be at least 1"); // Threshold of 0
    CheckUnparsable("multi(3,RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN,6Vacoawus3exy7CadokNypvNqMwDk77mXMKnyS66p5PSSzRihm9)", "multi(3,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "Multisig threshold cannot be larger than the number of keys; threshold is 3 but only 2 keys specified"); // Threshold larger than number of keys
    CheckUnparsable("multi(3,RB6Ezip4uy3ERmQw269etHFMXa9JHgB1dRAYL1G6Q6fphSQTXooR,R7ZSzk9gKnxN2NTFFW1M59CNAXf1QFHoYoGSKk9gjEZrSQDhk5RC,R96kZMKroL2iz4PQqjuu84dev2nwrCbuXkJQVdQUgE7DpZjiMM8g,RCUYPHWwaMdkfrQFedbfKLK7V84kCfrsXYaeTSdmmodfcMrYeUYQ)", "multi(3,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8)", "Cannot have 4 pubkeys in bare multisig; only at most 3 pubkeys"); // Threshold larger than number of keys
    CheckUnparsable("sh(multi(16,RB6Ezip4uy3ERmQw269etHFMXa9JHgB1dRAYL1G6Q6fphSQTXooR,R7ZSzk9gKnxN2NTFFW1M59CNAXf1QFHoYoGSKk9gjEZrSQDhk5RC,R96kZMKroL2iz4PQqjuu84dev2nwrCbuXkJQVdQUgE7DpZjiMM8g,RCUYPHWwaMdkfrQFedbfKLK7V84kCfrsXYaeTSdmmodfcMrYeUYQ,RC6pJutkuPp4qjzAgcLzoaowUQPFEweX7LPsnLwkmroZGKe1twae,R8WGP63wETM4VgxxkyeF9yV2HQS2LTdwVW47FcADFNu7sWgZTMTm,RFwhRNsNv8gUBayMnRujn17JZndWS3xjLASsntrFYoQVCXKMH6k9,RAYCV9s6MaAzeaJ1dSqDMp5QTRoobBzDDwsx51ZDQTzq2PZWu1FZ,RE5MVFQoPQzsbYky6CNL4GfBq1g9KCPmd8NXSYnwdSc7UKFYMedT,RA2Mogi7e8cWpsner9afKvMiwdwt3SKbmR3mQpbzn1bDSD48gJuG,R8AjyvvubqdCX1SkimAJkeNKEfpk2ZZy89YBpveWSt3V1yjwFvvV,RAVYbvJrGiNWjkiYgoofYYcQT3zTPxj6St586vC1iP47DniF32Ar,RAytMqZRzbQkrgexqWaSYHrctR4LuCbptG577KFdds471jSnMDU1,R9UbU3aYaVc5AwcmxpAJCrEi92ErCEmod56bEbhpiKpkVrUCR4u4,RAbHeoLRRoThRVV8Npccy5Vjhe9jwYfPPy1DrXVxj3RJ3bHcAjnW,RCFfJWaTvEu9RsGRxif9fVhzp7zv4C1rn2275SJkcWaPwQiMB123,RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN))","sh(multi(16,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", "P2SH script is too large, 581 bytes is larger than 520 bytes"); // Cannot have more than 15 keys in a P2SH multisig, or we exceed maximum push size
    Check("wsh(multi(20,RB6Ezip4uy3ERmQw269etHFMXa9JHgB1dRAYL1G6Q6fphSQTXooR,R7ZSzk9gKnxN2NTFFW1M59CNAXf1QFHoYoGSKk9gjEZrSQDhk5RC,R96kZMKroL2iz4PQqjuu84dev2nwrCbuXkJQVdQUgE7DpZjiMM8g,RCUYPHWwaMdkfrQFedbfKLK7V84kCfrsXYaeTSdmmodfcMrYeUYQ,RC6pJutkuPp4qjzAgcLzoaowUQPFEweX7LPsnLwkmroZGKe1twae,R8WGP63wETM4VgxxkyeF9yV2HQS2LTdwVW47FcADFNu7sWgZTMTm,RFwhRNsNv8gUBayMnRujn17JZndWS3xjLASsntrFYoQVCXKMH6k9,RAYCV9s6MaAzeaJ1dSqDMp5QTRoobBzDDwsx51ZDQTzq2PZWu1FZ,RE5MVFQoPQzsbYky6CNL4GfBq1g9KCPmd8NXSYnwdSc7UKFYMedT,RA2Mogi7e8cWpsner9afKvMiwdwt3SKbmR3mQpbzn1bDSD48gJuG,R8AjyvvubqdCX1SkimAJkeNKEfpk2ZZy89YBpveWSt3V1yjwFvvV,RAVYbvJrGiNWjkiYgoofYYcQT3zTPxj6St586vC1iP47DniF32Ar,RAytMqZRzbQkrgexqWaSYHrctR4LuCbptG577KFdds471jSnMDU1,R9UbU3aYaVc5AwcmxpAJCrEi92ErCEmod56bEbhpiKpkVrUCR4u4,RAbHeoLRRoThRVV8Npccy5Vjhe9jwYfPPy1DrXVxj3RJ3bHcAjnW,RCFfJWaTvEu9RsGRxif9fVhzp7zv4C1rn2275SJkcWaPwQiMB123,RAiieP4RV4kThHWPGKWrrurMW8KVWHeC5mFHnNCj1415MdQBDqic,RA2xpijZGLPvQn7NR3Bg4RH5bJZkuUrpMGyQrSGZKzPMHynGFj6z,RCW8RytsqfFXjrkKVKiCs73MTDj6TsqNf9vuPrVitPxBJf6fvz4i,R9dTaHZ2CGgxEhndtV3nKKVZm8y4m6uEiSmuKRA3WGXztr9KVvFe))","wsh(multi(20,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232,02bc2feaa536991d269aae46abb8f3772a5b3ad592314945e51543e7da84c4af6e,0318bf32e5217c1eb771a6d5ce1cd39395dff7ff665704f175c9a5451d95a2f2ca,02c681a6243f16208c2004bb81f5a8a67edfdd3e3711534eadeec3dcf0b010c759,0249fdd6b69768b8d84b4893f8ff84b36835c50183de20fcae8f366a45290d01fd))", "wsh(multi(20,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232,02bc2feaa536991d269aae46abb8f3772a5b3ad592314945e51543e7da84c4af6e,0318bf32e5217c1eb771a6d5ce1cd39395dff7ff665704f175c9a5451d95a2f2ca,02c681a6243f16208c2004bb81f5a8a67edfdd3e3711534eadeec3dcf0b010c759,0249fdd6b69768b8d84b4893f8ff84b36835c50183de20fcae8f366a45290d01fd))", SIGNABLE, {{"0020376bd8344b8b6ebe504ff85ef743eaa1aa9272178223bcb6887e9378efb341ac"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"2bb9d418ebdc3a75c465383985881527f3e5d6e520fb3efb152d4191b80e8412"}); // In P2WSH we can have up to 20 keys
    Check("sh(wsh(multi(20,RB6Ezip4uy3ERmQw269etHFMXa9JHgB1dRAYL1G6Q6fphSQTXooR,R7ZSzk9gKnxN2NTFFW1M59CNAXf1QFHoYoGSKk9gjEZrSQDhk5RC,R96kZMKroL2iz4PQqjuu84dev2nwrCbuXkJQVdQUgE7DpZjiMM8g,RCUYPHWwaMdkfrQFedbfKLK7V84kCfrsXYaeTSdmmodfcMrYeUYQ,RC6pJutkuPp4qjzAgcLzoaowUQPFEweX7LPsnLwkmroZGKe1twae,R8WGP63wETM4VgxxkyeF9yV2HQS2LTdwVW47FcADFNu7sWgZTMTm,RFwhRNsNv8gUBayMnRujn17JZndWS3xjLASsntrFYoQVCXKMH6k9,RAYCV9s6MaAzeaJ1dSqDMp5QTRoobBzDDwsx51ZDQTzq2PZWu1FZ,RE5MVFQoPQzsbYky6CNL4GfBq1g9KCPmd8NXSYnwdSc7UKFYMedT,RA2Mogi7e8cWpsner9afKvMiwdwt3SKbmR3mQpbzn1bDSD48gJuG,R8AjyvvubqdCX1SkimAJkeNKEfpk2ZZy89YBpveWSt3V1yjwFvvV,RAVYbvJrGiNWjkiYgoofYYcQT3zTPxj6St586vC1iP47DniF32Ar,RAytMqZRzbQkrgexqWaSYHrctR4LuCbptG577KFdds471jSnMDU1,R9UbU3aYaVc5AwcmxpAJCrEi92ErCEmod56bEbhpiKpkVrUCR4u4,RAbHeoLRRoThRVV8Npccy5Vjhe9jwYfPPy1DrXVxj3RJ3bHcAjnW,RCFfJWaTvEu9RsGRxif9fVhzp7zv4C1rn2275SJkcWaPwQiMB123,RAiieP4RV4kThHWPGKWrrurMW8KVWHeC5mFHnNCj1415MdQBDqic,RA2xpijZGLPvQn7NR3Bg4RH5bJZkuUrpMGyQrSGZKzPMHynGFj6z,RCW8RytsqfFXjrkKVKiCs73MTDj6TsqNf9vuPrVitPxBJf6fvz4i,R9dTaHZ2CGgxEhndtV3nKKVZm8y4m6uEiSmuKRA3WGXztr9KVvFe)))","sh(wsh(multi(20,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232,02bc2feaa536991d269aae46abb8f3772a5b3ad592314945e51543e7da84c4af6e,0318bf32e5217c1eb771a6d5ce1cd39395dff7ff665704f175c9a5451d95a2f2ca,02c681a6243f16208c2004bb81f5a8a67edfdd3e3711534eadeec3dcf0b010c759,0249fdd6b69768b8d84b4893f8ff84b36835c50183de20fcae8f366a45290d01fd)))", "sh(wsh(multi(20,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232,02bc2feaa536991d269aae46abb8f3772a5b3ad592314945e51543e7da84c4af6e,0318bf32e5217c1eb771a6d5ce1cd39395dff7ff665704f175c9a5451d95a2f2ca,02c681a6243f16208c2004bb81f5a8a67edfdd3e3711534eadeec3dcf0b010c759,0249fdd6b69768b8d84b4893f8ff84b36835c50183de20fcae8f366a45290d01fd)))", SIGNABLE, {{"a914c2c9c510e9d7f92fd6131e94803a8d34a8ef675e87"}}, OutputType::P2SH_SEGWIT, /*op_desc_id=*/uint256{"69c3f3153ed2527d12cf78e53e719233fdb7fa6ca9f8a10059ce47d34b49c4cb"}); // Even if it's wrapped into P2SH
    // Check for invalid nesting of structures
    CheckUnparsable("sh(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "sh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "A function is needed within P2SH"); // P2SH needs a script, not a key
    CheckUnparsable("sh(combo(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN))", "sh(combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", "Can only have combo() at top level"); // Old must be top level
    CheckUnparsable("wsh(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)", "wsh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "A function is needed within P2WSH"); // P2WSH needs a script, not a key
    CheckUnparsable("wsh(wpkh(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN))", "wsh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", "Can only have wpkh() at top level or inside sh()"); // Cannot embed witness inside witness
    CheckUnparsable("wsh(sh(pk(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)))", "wsh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))", "Can only have sh() at top level"); // Cannot embed P2SH inside P2WSH
    CheckUnparsable("sh(sh(pk(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)))", "sh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))", "Can only have sh() at top level"); // Cannot embed P2SH inside P2SH
    CheckUnparsable("wsh(wsh(pk(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)))", "wsh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))", "Can only have wsh() at top level or inside sh()"); // Cannot embed P2WSH inside P2WSH

    // Checksums
    Check("sh(multi(2,[00000000/111'/222]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0))#t97hujet", "sh(multi(2,[00000000/111'/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))#mhuctdq3", "sh(multi(2,[00000000/111h/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))#8d08ka88", DEFAULT, {{"a91445a9a622a8b0a1269944be477640eedc447bbd8487"}}, OutputType::LEGACY, /*op_desc_id=*/uint256{"078a87224a1d194499cbcba74a91b347f556fafff3197870e20230c0646066a4"}, {{0x8000006FUL,222},{0}});
    Check("sh(multi(2,[00000000/111'/222]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0))", "sh(multi(2,[00000000/111'/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))", "sh(multi(2,[00000000/111h/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))", DEFAULT, {{"a91445a9a622a8b0a1269944be477640eedc447bbd8487"}}, OutputType::LEGACY, /*op_desc_id=*/uint256{"078a87224a1d194499cbcba74a91b347f556fafff3197870e20230c0646066a4"}, {{0x8000006FUL,222},{0}});
    CheckUnparsable("sh(multi(2,[00000000/111'/222]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0))#", "sh(multi(2,[00000000/111'/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))#", "Expected 8 character checksum, not 0 characters"); // Empty checksum
    CheckUnparsable("sh(multi(2,[00000000/111'/222]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0))#t97hujetq", "sh(multi(2,[00000000/111'/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))#mhuctdq3q", "Expected 8 character checksum, not 9 characters"); // Too long checksum
    CheckUnparsable("sh(multi(2,[00000000/111'/222]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0))#t97huje", "sh(multi(2,[00000000/111'/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))#mhuctdq", "Expected 8 character checksum, not 7 characters"); // Too short checksum
    CheckUnparsable("sh(multi(3,[00000000/111'/222]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0))#t97hujet", "sh(multi(3,[00000000/111'/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))#mhuctdq3", "Provided checksum 'mhuctdq3' does not match computed checksum 'asjcjdsk'"); // Error in payload
    CheckUnparsable("sh(multi(2,[00000000/111'/222]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0))#t98hujet", "sh(multi(2,[00000000/111'/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))#mhuctdq9", "Provided checksum 'mhuctdq9' does not match computed checksum 'mhuctdq3'"); // Error in checksum
    CheckUnparsable("sh(multi(2,[00000000/111'/222]rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0))##ggssrxfy", "sh(multi(2,[00000000/111'/222]rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0))##tjq09x4t", "Multiple '#' symbols"); // Error in checksum

    // Addr and raw tests
    CheckUnparsable("", "addr(asdf)", "Address is not valid"); // Invalid address
    CheckUnparsable("", "raw(asdf)", "Raw script is not hex"); // Invalid script
    CheckUnparsable("", "raw(Ü)#00000000", "Invalid characters in payload"); // Invalid chars

    Check(
        "rawtr(rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3/86'/1'/0'/1/*)#xldpqcf8",
        "rawtr(rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1/86'/1'/0'/1/*)#h2mpr5l8",
        "rawtr([5a61ff8e/86h/1h/0h]rpub4Gtyzc7tXEmJ13o6N8G8WkbZ9znY7ny5wRC5Xwwx7HSNm4biX2wrA53tJw52Vs7nLhqEpcsKxEpRDnQZaSeuKvGakQxpPcxKESkrZ66Dbo2/1/*)#fv69r6sa",
        RANGE | HARDENED | XONLY_KEYS,
        {{"51205172af752f057d543ce8e4a6f8dcf15548ec6be44041bfa93b72e191cfc8c1ee"}, {"51201b66f20b86f700c945ecb9ad9b0ad1662b73084e2bfea48bee02126350b8a5b1"}, {"512063e70f66d815218abcc2306aa930aaca07c5cde73b75127eb27b5e8c16b58a25"}},
        OutputType::BECH32M,
        /*op_desc_id=*/uint256{"cf27fb93d90f4e1cdf61cdaf4c11d6ea3e4e134d04cccae44d77094ad126722a"},
        {{0x80000056, 0x80000001, 0x80000000, 1, 0}, {0x80000056, 0x80000001, 0x80000000, 1, 1}, {0x80000056, 0x80000001, 0x80000000, 1, 2}});

    Check(
        "rawtr(RF9P2cqNKtia2eN7TTLU1pWbNTQKFFzsWxhwv5jWenN3KSmkVQZN)",
        "rawtr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        "rawtr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
        SIGNABLE | XONLY_KEYS,
        {{"5120a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"}},
        OutputType::BECH32M,
        /*op_desc_id=*/uint256{"5ba3f7d83cee4795df00e0eaa5070a3e164283c5fc6e8586fd710eaa7a4168ec"});

    CheckUnparsable(
        "",
        "rawtr(xpub68FQ9imX6mCWacw6eNRjaa8q8ynnHmUd5i7MVR51ZMPP5JycyfVHSLQVFPHMYiTybWJnSBL2tCBpy6aJTR2DYrshWYfwAxs8SosGXd66d8/*, rpub4CNM13NrpjP3gqzzApviXvWipwjWFcHrzLsi6VuLmoapyndcMf9v3zkNkMF81H68ScFBdqp5UA5ov4wFwQtZ9eE4vQntAGK6ety3ftRkAKN/*)",
        "rawtr(): only one key expected.");

    // A 2of4 but using a direct push rather than OP_2
    CScript nonminimalmultisig;
    CKey keys[4];
    nonminimalmultisig << std::vector<unsigned char>{2};
    for (int i = 0; i < 4; i++) {
        keys[i].MakeNewKey(true);
        nonminimalmultisig << ToByteVector(keys[i].GetPubKey());
    }
    nonminimalmultisig << 4 << OP_CHECKMULTISIG;
    CheckInferRaw(nonminimalmultisig);

    // A 2of4 but using a direct push rather than OP_4
    nonminimalmultisig.clear();
    nonminimalmultisig << 2;
    for (int i = 0; i < 4; i++) {
        keys[i].MakeNewKey(true);
        nonminimalmultisig << ToByteVector(keys[i].GetPubKey());
    }
    nonminimalmultisig << std::vector<unsigned char>{4} << OP_CHECKMULTISIG;
    CheckInferRaw(nonminimalmultisig);

    // Miniscript tests

    // Invalid checksum
    CheckUnparsable("wsh(and_v(vc:andor(pk(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh),pk_k(R8SMCsLkrKKRnbqapWFLrAghGqEw9J92TYpCorTXPVeRmKrZCMx1),and_v(v:older(1),pk_k(RF66ksY1ebV68bu3Fqc4mXvPM7YiHH4E3UtSE1tERUgZFc3Jv6Ar))),after(10)))#abcdef12", "wsh(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))#abcdef12", "Provided checksum 'abcdef12' does not match computed checksum 'tyzp6a7p'");
    // Only p2wsh or tr contexts are valid
    CheckUnparsable("sh(and_v(vc:andor(pk(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh),pk_k(R8SMCsLkrKKRnbqapWFLrAghGqEw9J92TYpCorTXPVeRmKrZCMx1),and_v(v:older(1),pk_k(RF66ksY1ebV68bu3Fqc4mXvPM7YiHH4E3UtSE1tERUgZFc3Jv6Ar))),after(10)))", "sh(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "Miniscript expressions can only be used in wsh or tr.");
    CheckUnparsable("tr(and_v(vc:andor(pk(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh),pk_k(R8SMCsLkrKKRnbqapWFLrAghGqEw9J92TYpCorTXPVeRmKrZCMx1),and_v(v:older(1),pk_k(RF66ksY1ebV68bu3Fqc4mXvPM7YiHH4E3UtSE1tERUgZFc3Jv6Ar))),after(10)))", "tr(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "tr(): key 'and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10))' is not valid");
    CheckUnparsable("raw(and_v(vc:andor(pk(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh),pk_k(R8SMCsLkrKKRnbqapWFLrAghGqEw9J92TYpCorTXPVeRmKrZCMx1),and_v(v:older(1),pk_k(RF66ksY1ebV68bu3Fqc4mXvPM7YiHH4E3UtSE1tERUgZFc3Jv6Ar))),after(10)))", "sh(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "Miniscript expressions can only be used in wsh or tr.");
    CheckUnparsable("", "tr(034D2224bbbbbbbbbbcbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb40,{{{{{{{{{{{{{{{{{{{{{{multi(1,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/967808'/9,xprvA1RpRA33e1JQ7ifknakTFNpgXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/968/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/3/4/5/58/55/2/5/58/58/2/5/5/5/8/5/2/8/5/85/2/8/2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/8/5/8/5/4/5/585/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/8/2/5/8/5/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/58/58/2/0/8/5/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/5/8/5/8/24/5/58/52/5/8/5/2/8/24/5/58/588/246/8/5/2/8/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/5/4/5/58/55/58/2/5/8/55/2/5/8/58/555/58/2/5/8/4//2/5/58/5w/2/5/8/5/2/4/5/58/5558'/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/8/2/5/8/5/5/8/58/2/5/58/58/2/5/8/9/588/2/58/2/5/8/5/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/82/5/8/5/5/58/52/6/8/5/2/8/{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{}{{{{{{{{{DDD2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8588/246/8/5/2DLDDDDDDDbbD3DDDD/8/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/3/4/5/58/55/2/5/58/58/2/5/5/5/8/5/2/8/5/85/2/8/2/5/8D)/5/2/5/58/58/2/5/58/58/58/588/2/58/2/5/8/5/25/58/58/2/5/58/58/2/5/8/9/588/2/58/2/6780,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFW/8/5/2/5/58678008')", "'multi(1,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb/967808'/9,xprvA1RpRA33e1JQ7ifknakTFNpgXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/968/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/3/4/5/58/55/2/5/58/58/2/5/5/5/8/5/2/8/5/85/2/8/2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/8/5/8/5/4/5/585/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/8/2/5/8/5/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/58/58/2/0/8/5/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/5/8/5/8/24/5/58/52/5/8/5/2/8/24/5/58/588/246/8/5/2/8/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/5/4/5/58/55/58/2/5/8/55/2/5/8/58/555/58/2/5/8/4//2/5/58/5w/2/5/8/5/2/4/5/58/5558'/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/8/2/5/8/5/5/8/58/2/5/58/58/2/5/8/9/588/2/58/2/5/8/5/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/82/5/8/5/5/58/52/6/8/5/2/8/{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{}{{{{{{{{{DDD2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8588/246/8/5/2DLDDDDDDDbbD3DDDD/8/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/3/4/5/58/55/2/5/58/58/2/5/5/5/8/5/2/8/5/85/2/8/2/5/8D)/5/2/5/58/58/2/5/58/58/58/588/2/58/2/5/8/5/25/58/58/2/5/58/58/2/5/8/9/588/2/58/2/6780,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFW/8/5/2/5/58678008'' is not a valid descriptor function");
    // No uncompressed keys allowed
    CheckUnparsable("", "wsh(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(049228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4))),after(10)))", "Uncompressed keys are not allowed");
    // No hybrid keys allowed
    CheckUnparsable("", "wsh(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(069228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4))),after(10)))", "Hybrid public keys are not allowed");
    // Insane at top level
    CheckUnparsable("wsh(and_b(vc:andor(pk(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh),pk_k(R8SMCsLkrKKRnbqapWFLrAghGqEw9J92TYpCorTXPVeRmKrZCMx1),and_v(v:older(1),pk_k(RF66ksY1ebV68bu3Fqc4mXvPM7YiHH4E3UtSE1tERUgZFc3Jv6Ar))),after(10)))", "wsh(and_b(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "and_b(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)) is invalid");
    // Invalid sub
    CheckUnparsable("wsh(and_v(vc:andor(v:pk_k(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh),pk_k(R8SMCsLkrKKRnbqapWFLrAghGqEw9J92TYpCorTXPVeRmKrZCMx1),and_v(v:older(1),pk_k(RF66ksY1ebV68bu3Fqc4mXvPM7YiHH4E3UtSE1tERUgZFc3Jv6Ar))),after(10)))", "wsh(and_v(vc:andor(v:pk_k(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "v:pk_k(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204) is invalid");
    // Insane subs
    CheckUnparsable("wsh(or_i(older(1),pk(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh)))", "wsh(or_i(older(1),pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)))", "or_i(older(1),pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)) is not sane: witnesses without signature exist");
    CheckUnparsable("wsh(or_b(sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)))", "wsh(or_b(sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)))", "or_b(sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)) is not sane: malleable witnesses exist");
    CheckUnparsable("wsh(and_b(and_b(older(1),a:older(100000000)),s:pk(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh)))", "wsh(and_b(and_b(older(1),a:older(100000000)),s:pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)))", "and_b(older(1),a:older(100000000)) is not sane: contains mixes of timelocks expressed in blocks and seconds");
    CheckUnparsable("wsh(and_b(or_b(pkh(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh),s:pk(R8SMCsLkrKKRnbqapWFLrAghGqEw9J92TYpCorTXPVeRmKrZCMx1)),s:pk(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh)))", "wsh(and_b(or_b(pkh(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0)),s:pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)))", "and_b(or_b(pkh(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0)),s:pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)) is not sane: contains duplicate public keys");
    // Valid with extended keys.
    Check("wsh(and_v(v:ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e),multi(1,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0)))", "wsh(and_v(v:ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e),multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0)))", "wsh(and_v(v:ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e),multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0)))", DEFAULT, {{"0020acf425291b98a1d7e0d4690139442abc289175be32ef1f75945e339924246d73"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"4d34414a9b8c9b5f4b2ec2dd15db90c34bf18b55ee2357f3e9d80b9ac7e8f2c0"}, {{},{0}});
    // Valid under sh(wsh()) and with a mix of xpubs and raw keys.
    Check("sh(wsh(thresh(1,pkh(REyR1to86fSds7L93oY5etyPR2bG2gGPW4dD4F6Kkr16KWtewzjh),a:and_n(multi(1,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0),n:older(2)))))", "sh(wsh(thresh(1,pkh(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),a:and_n(multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0),n:older(2)))))", "sh(wsh(thresh(1,pkh(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),a:and_n(multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0),n:older(2)))))", SIGNABLE | MIXED_PUBKEYS, {{"a914767e9119ff3b3ac0cb6dcfe21de1842ccf85f1c487"}}, OutputType::P2SH_SEGWIT, /*op_desc_id=*/uint256{"ae71f19d3c15db669598ecb071419a10568f6966ec0fc4e3cd4db93444a5cf6f"}, {{},{0}});
    // An exotic multisig, we can sign for both branches
    Check("wsh(thresh(1,pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb),a:pkh(rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0)))", "wsh(thresh(1,pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE),a:pkh(rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0)))", "wsh(thresh(1,pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE),a:pkh(rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0)))", SIGNABLE, {{"00204a4528fbc0947e02e921b54bd476fc8cc2ebb5c6ae2ccf10ed29fe2937fb6892"}}, OutputType::BECH32, /*op_desc_id=*/std::nullopt, {{},{0}});
    // We can sign for a script requiring the two kinds of timelock.
    // But if we don't set a sequence high enough, we'll fail.
    Check("sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0),n:older(2)))))", SIGNABLE_FAILS, {{"a914099f400961f930d4c16c3b33c0e2a58ef53ac38f87"}}, OutputType::P2SH_SEGWIT, /*op_desc_id=*/uint256{"d72ec5a5122ec4d5518a3b278de96c46a52a8a002cc47e12b8b94fa30e17c56c"}, {{},{0}}, /*spender_nlocktime=*/1000, /*spender_nsequence=*/1);
    // And same for the nLockTime.
    Check("sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0),n:older(2)))))", SIGNABLE_FAILS, {{"a914099f400961f930d4c16c3b33c0e2a58ef53ac38f87"}}, OutputType::P2SH_SEGWIT, /*op_desc_id=*/uint256{"d72ec5a5122ec4d5518a3b278de96c46a52a8a002cc47e12b8b94fa30e17c56c"}, {{},{0}}, /*spender_nlocktime=*/999, /*spender_nsequence=*/2);
    // But if both are set to (at least) the required value, we'll succeed.
    Check("sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb,rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE,rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw/0),n:older(2)))))", SIGNABLE, {{"a914099f400961f930d4c16c3b33c0e2a58ef53ac38f87"}}, OutputType::P2SH_SEGWIT, /*op_desc_id=*/uint256{"d72ec5a5122ec4d5518a3b278de96c46a52a8a002cc47e12b8b94fa30e17c56c"}, {{},{0}}, /*spender_nlocktime=*/1000, /*spender_nsequence=*/2);
    // We can't sign for a script requiring a ripemd160 preimage without providing it.
    Check("wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)))", "wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", "wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", SIGNABLE_FAILS, {{"002001549deda34cbc4a5982263191380f522695a2ddc2f99fc3a65c736264bd6cab"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"f2cc8a06915be4a0bfac532c62b055bf2aa40eeeb69860cb3530ccd38484fbd9"}, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {});
    // But if we provide it, we can.
    Check("wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)))", "wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", "wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", SIGNABLE, {{"002001549deda34cbc4a5982263191380f522695a2ddc2f99fc3a65c736264bd6cab"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"f2cc8a06915be4a0bfac532c62b055bf2aa40eeeb69860cb3530ccd38484fbd9"}, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {{"ff9aa1829c90d26e73301383f549e1497b7d6325"_hex_v_u8, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"_hex_v_u8}});
    // Same for sha256
    Check("wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)))", "wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", "wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", SIGNABLE_FAILS, {{"002071f7283dbbb9a55ed43a54cda16ba0efd0f16dc48fe200f299e57bb5d7be8dd4"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"53cae744d0aa3957ab725f947a7d02600ef58f405d7d1b3f50293a8e16b840bb"}, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {});
    Check("wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)))", "wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", "wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", SIGNABLE, {{"002071f7283dbbb9a55ed43a54cda16ba0efd0f16dc48fe200f299e57bb5d7be8dd4"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"53cae744d0aa3957ab725f947a7d02600ef58f405d7d1b3f50293a8e16b840bb"}, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {{"7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863"_hex_v_u8, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"_hex_v_u8}});
    // Same for hash160
    Check("wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)))", "wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", "wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", SIGNABLE_FAILS, {{"00209b9d5b45735d0e15df5b41d6594602d3de472262f7b75edc6cf5f3e3fa4e3ae4"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"0a77cb083ba86f86a6c0c78b5053706c71d63a789db4bf1fa310fa58bc57ac95"}, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {});
    Check("wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)))", "wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", "wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", SIGNABLE, {{"00209b9d5b45735d0e15df5b41d6594602d3de472262f7b75edc6cf5f3e3fa4e3ae4"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"0a77cb083ba86f86a6c0c78b5053706c71d63a789db4bf1fa310fa58bc57ac95"}, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {{"292e2df59e3a22109200beed0cdc84b12e66793e"_hex_v_u8, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"_hex_v_u8}});
    // Same for hash256
    Check("wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)))", "wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", "wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", SIGNABLE_FAILS, {{"0020cf62bf97baf977aec69cbc290c372899f913337a9093e8f066ab59b8657a365c"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"d3c6754b82a01516c5715deef13bfc1c7218fe0096af157abc1223d3852f7e49"}, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {});
    Check("wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb)))", "wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", "wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE)))", SIGNABLE, {{"0020cf62bf97baf977aec69cbc290c372899f913337a9093e8f066ab59b8657a365c"}}, OutputType::BECH32, /*op_desc_id=*/uint256{"d3c6754b82a01516c5715deef13bfc1c7218fe0096af157abc1223d3852f7e49"}, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {{"ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588"_hex_v_u8, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"_hex_v_u8}});
    // Can have a Miniscript expression under tr() if it's alone.
    Check("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,thresh(2,pk(RBfPMnEyHPkt8tQ7DRZGQwxWDxCPn7PUdE7uQfTYmzok7zX4Qihd),s:pk(RALnCqaXQkLCBK2PaWycdsWPxayfqsJ9c6Hvja4537Vo2LtyJX4s),adv:older(42)))", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,thresh(2,pk(30a6069f344fb784a2b4c99540a91ee727c91e3a25ef6aae867d9c65b5f23529),s:pk(9918d400c1b8c3c478340a40117ced4054b6b58f48cdb3c89b836bdfee1f5766),adv:older(42)))", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,thresh(2,pk(30a6069f344fb784a2b4c99540a91ee727c91e3a25ef6aae867d9c65b5f23529),s:pk(9918d400c1b8c3c478340a40117ced4054b6b58f48cdb3c89b836bdfee1f5766),adv:older(42)))", MISSING_PRIVKEYS | XONLY_KEYS | SIGNABLE, {{"512033982eebe204dc66508e4b19cfc31b5ffc6e1bfcbf6e5597dfc2521a52270795"}}, OutputType::BECH32M);
    // Can have a pkh() expression alone as tr() script path (because pkh() is valid Miniscript).
    Check("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pkh(RBfPMnEyHPkt8tQ7DRZGQwxWDxCPn7PUdE7uQfTYmzok7zX4Qihd))", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pkh(30a6069f344fb784a2b4c99540a91ee727c91e3a25ef6aae867d9c65b5f23529))", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pkh(30a6069f344fb784a2b4c99540a91ee727c91e3a25ef6aae867d9c65b5f23529))", MISSING_PRIVKEYS | XONLY_KEYS | SIGNABLE, {{"51201e9875f690f5847404e4c5951e2f029887df0525691ee11a682afd37b608aad4"}}, OutputType::BECH32M);
    // Can have a Miniscript expression under tr() if it's part of a tree.
    Check("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{{pkh(RA3YQR2ZGUB4Aatsi8TTnF4R4gB2b51RKKCLXwhErVtiFvdEYwfg),pk(RDXrzWdDP4XeALUwwnJ4d74DhJeCydXzpVL8Q5SWQnNo6SoU35YV)},thresh(1,pk(RBfPMnEyHPkt8tQ7DRZGQwxWDxCPn7PUdE7uQfTYmzok7zX4Qihd),s:pk(RALnCqaXQkLCBK2PaWycdsWPxayfqsJ9c6Hvja4537Vo2LtyJX4s))})", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{{pkh(1c9bc926084382e76da33b5a52d17b1fa153c072aae5fb5228ecc2ccf89d79d5),pk(0dd6b52b192ab195558d22dd8437a9ec4519ee5ded496c0d55bc9b1a8b0e8c2b)},thresh(1,pk(30a6069f344fb784a2b4c99540a91ee727c91e3a25ef6aae867d9c65b5f23529),s:pk(9918d400c1b8c3c478340a40117ced4054b6b58f48cdb3c89b836bdfee1f5766))})", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{{pkh(1c9bc926084382e76da33b5a52d17b1fa153c072aae5fb5228ecc2ccf89d79d5),pk(0dd6b52b192ab195558d22dd8437a9ec4519ee5ded496c0d55bc9b1a8b0e8c2b)},thresh(1,pk(30a6069f344fb784a2b4c99540a91ee727c91e3a25ef6aae867d9c65b5f23529),s:pk(9918d400c1b8c3c478340a40117ced4054b6b58f48cdb3c89b836bdfee1f5766))})", MISSING_PRIVKEYS | XONLY_KEYS, {{"5120d8ea39b29de2b550b68bd2ada8b075c888c2b2df3290c7a35856482747848934"}}, OutputType::BECH32M);
    // Can have two Miniscripts in a Taproot with mixed private and public keys, and mixed ranged extended keys and raw keys.
    Check("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(v:pk(rpub4DH1rdJ7GBPbQo7fK8K3oLrui63cYYc1tGiy8yvufAoK3QXYRSR59FhLRWe3GwxVocU9QFD9Wu4kMeMQYzkG4vJ1DLjQSPApPAk7Aef9f7o/*),pk(02daf6e3477fc3906a1997820ed2940c8f5fa0942946d0368f981b001fdd85afcb)),and_v(v:pk(rprv7zCnHtSLTyuamz2ZEa2A87ufNvttWAy3n6WBeQEESrua5GGzD9tqHXDcawvF4fq7MsQkiKb9CWS52dLySUKpbtzASk2vTjTeFtaYWrLn5aq/*),pk(03272c0c1ae2c07528283b91ca57b45d2cc84e7960e1f17f58815372285f35e99a))})", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(v:pk(rpub4DH1rdJ7GBPbQo7fK8K3oLrui63cYYc1tGiy8yvufAoK3QXYRSR59FhLRWe3GwxVocU9QFD9Wu4kMeMQYzkG4vJ1DLjQSPApPAk7Aef9f7o/*),pk(02daf6e3477fc3906a1997820ed2940c8f5fa0942946d0368f981b001fdd85afcb)),and_v(v:pk(rpub4DC8hPyEJMTszU72LbZAVFrPvxjNudgu9KRnSndr1CSYx4c8khD5qKY6SDh92KTFpeC8sz7JUBXDGpxA7TjEoyTEUoXbpsadpR8uzwwBCnb/*),pk(03272c0c1ae2c07528283b91ca57b45d2cc84e7960e1f17f58815372285f35e99a))})", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(v:pk(rpub4DH1rdJ7GBPbQo7fK8K3oLrui63cYYc1tGiy8yvufAoK3QXYRSR59FhLRWe3GwxVocU9QFD9Wu4kMeMQYzkG4vJ1DLjQSPApPAk7Aef9f7o/*),pk(02daf6e3477fc3906a1997820ed2940c8f5fa0942946d0368f981b001fdd85afcb)),and_v(v:pk(rpub4DC8hPyEJMTszU72LbZAVFrPvxjNudgu9KRnSndr1CSYx4c8khD5qKY6SDh92KTFpeC8sz7JUBXDGpxA7TjEoyTEUoXbpsadpR8uzwwBCnb/*),pk(03272c0c1ae2c07528283b91ca57b45d2cc84e7960e1f17f58815372285f35e99a))})", MISSING_PRIVKEYS | XONLY_KEYS | RANGE | MIXED_PUBKEYS, {{"5120793185cd1a9a0bb710fa57df3845ac4ddf7df63b74beadce2573cbb0b508b3a4"}}, OutputType::BECH32M, /*op_desc_id=*/{}, {{}, {0}});
    // Can sign for a Miniscript expression containing a hash challenge inside a Taproot tree. (Fails without the
    // preimages and the sequence, passes with.)
    Check("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(RA3YQR2ZGUB4Aatsi8TTnF4R4gB2b51RKKCLXwhErVtiFvdEYwfg)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,RBBRzdKVwuYi1g8BnpvZrawp1ZCpLb9iBic11NYPPEwsPYXFuCGN)})", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(1c9bc926084382e76da33b5a52d17b1fa153c072aae5fb5228ecc2ccf89d79d5)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,14fa4ad085cdee1e2fc73d491b36a96c192382b1d9a21108eb3533f630364f9f)})", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(1c9bc926084382e76da33b5a52d17b1fa153c072aae5fb5228ecc2ccf89d79d5)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,14fa4ad085cdee1e2fc73d491b36a96c192382b1d9a21108eb3533f630364f9f)})", MISSING_PRIVKEYS | XONLY_KEYS | SIGNABLE | SIGNABLE_FAILS, {{"51209a3d79db56fbe3ba4d905d827b62e1ed31cd6df1198b8c759d589c0f4efc27bd"}}, OutputType::BECH32M);
    Check("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(RA3YQR2ZGUB4Aatsi8TTnF4R4gB2b51RKKCLXwhErVtiFvdEYwfg)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,RBBRzdKVwuYi1g8BnpvZrawp1ZCpLb9iBic11NYPPEwsPYXFuCGN)})", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(1c9bc926084382e76da33b5a52d17b1fa153c072aae5fb5228ecc2ccf89d79d5)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,14fa4ad085cdee1e2fc73d491b36a96c192382b1d9a21108eb3533f630364f9f)})", "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(1c9bc926084382e76da33b5a52d17b1fa153c072aae5fb5228ecc2ccf89d79d5)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,14fa4ad085cdee1e2fc73d491b36a96c192382b1d9a21108eb3533f630364f9f)})", MISSING_PRIVKEYS | XONLY_KEYS | SIGNABLE, {{"51209a3d79db56fbe3ba4d905d827b62e1ed31cd6df1198b8c759d589c0f4efc27bd"}}, OutputType::BECH32M, /*op_desc_id=*/{}, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/42, /*preimages=*/{{"ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588"_hex_v_u8, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"_hex_v_u8}});

    // Basic sh(pkh()) with key origin
    CheckInferDescriptor("a9141a31ad23bf49c247dd531a623c2ef57da3c400c587", "sh(pkh([deadbeef/0h/0h/0]03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", {"76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac"}, {{"03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd", "deadbeef/0h/0h/0"}});
    // p2pk script with hybrid key must infer as raw()
    CheckInferDescriptor("41069228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4ac", "raw(41069228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4ac)", {}, {{"069228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4", ""}});
    // p2pkh script with hybrid key must infer as addr()
    CheckInferDescriptor("76a91445ff7c2327866472639d507334a9a00119dfd32688ac", "addr(RFfJm9xNqrDBhJL9tMZ9UWKyQziHHjzj7u)", {}, {{"069228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4", ""}});
    // p2wpkh script with uncompressed key must infer as addr()
    CheckInferDescriptor("001422e363a523947a110d9a9eb114820de183aca313", "addr(rub1qyt3k8ffrj3apzrv6n6c3fqsduxp6egcnxgj6uk)", {}, {{"049228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4", ""}});
    // Infer pkh() from p2pkh with uncompressed key
    CheckInferDescriptor("76a914a31725c74421fadc50d35520ab8751ed120af80588ac", "pkh(04c56fe4a92d401bcbf1b3dfbe4ac3dac5602ca155a3681497f02c1b9a733b92d704e2da6ec4162e4846af9236ef4171069ac8b7f8234a8405b6cadd96f34f5a31)", {}, {{"04c56fe4a92d401bcbf1b3dfbe4ac3dac5602ca155a3681497f02c1b9a733b92d704e2da6ec4162e4846af9236ef4171069ac8b7f8234a8405b6cadd96f34f5a31", ""}});
    // Infer pk() from p2pk with uncompressed key
    CheckInferDescriptor("4104032540df1d3c7070a8ab3a9cdd304dfc7fd1e6541369c53c4c3310b2537d91059afc8b8e7673eb812a32978dabb78c40f2e423f7757dca61d11838c7aeeb5220ac", "pk(04032540df1d3c7070a8ab3a9cdd304dfc7fd1e6541369c53c4c3310b2537d91059afc8b8e7673eb812a32978dabb78c40f2e423f7757dca61d11838c7aeeb5220)", {}, {{"04032540df1d3c7070a8ab3a9cdd304dfc7fd1e6541369c53c4c3310b2537d91059afc8b8e7673eb812a32978dabb78c40f2e423f7757dca61d11838c7aeeb5220", ""}});
}

BOOST_AUTO_TEST_SUITE_END()
