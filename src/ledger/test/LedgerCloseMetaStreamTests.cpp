// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/Hex.h"
#include "crypto/Random.h"
#include "crypto/SecretKey.h"
#include "history/HistoryArchiveManager.h"
#include "history/test/HistoryTestsUtils.h"
#include "ledger/FlushAndRotateMetaDebugWork.h"
#include "ledger/LedgerTxn.h"
#include "ledger/test/LedgerTestUtils.h"
#include "lib/catch.hpp"
#include "main/Application.h"
#include "main/ApplicationUtils.h"
#include "simulation/Simulation.h"
#include "test/TestUtils.h"
#include "test/TxTests.h"
#include "test/test.h"
#include "util/Logging.h"
#include "util/ProtocolVersion.h"
#include "util/XDRCereal.h"
#include "util/XDRStream.h"
#include "work/WorkScheduler.h"
#include "xdr/Stellar-ledger.h"
#include "xdr/Stellar-transaction.h"
#include <fmt/format.h>
#include <fstream>
#include <iterator>

using namespace stellar;

TEST_CASE("LedgerCloseMetaStream file descriptor - LIVE_NODE",
          "[ledgerclosemetastreamlive]")
{
    // Live reqires a multinode simulation, as we're not allowed to run a
    // validator and record metadata streams at the same time (to avoid the
    // unbounded-latency stream-write step): N nodes participating in consensus,
    // and two watching and streaming metadata -- the second one using
    // EXPERIMENTAL_PRECAUTION_DELAY_META.

    Hash expectedLastUnsafeHash, expectedLastSafeHash;
    TmpDirManager tdm(std::string("streamtmp-") + binToHex(randomBytes(8)));
    TmpDir td = tdm.tmpDir("streams");
    std::string metaPath = td.getName() + "/stream.xdr";
    std::string metaPathSafe = td.getName() + "/streamSafe.xdr";

    uint32 const ledgerToWaitFor = 10;

    bool const induceOneLedgerFork = GENERATE(false, true);
    CAPTURE(induceOneLedgerFork);
    auto const ledgerToCorrupt = 5;
    static_assert(ledgerToCorrupt < ledgerToWaitFor,
                  "must wait beyond corrupt ledger");

    auto const expectedLastWatcherLedger =
        induceOneLedgerFork ? ledgerToCorrupt : ledgerToWaitFor;

    {
        // Step 1: Set up a 5 node simulation with 3 validators and 2 watchers.
        auto networkID = sha256(getTestConfig().NETWORK_PASSPHRASE);
        auto simulation =
            std::make_shared<Simulation>(Simulation::OVER_LOOPBACK, networkID);

        SIMULATION_CREATE_NODE(Node1); // Validator
        SIMULATION_CREATE_NODE(Node2); // Validator
        SIMULATION_CREATE_NODE(Node3); // Validator

        // Watcher, !EXPERIMENTAL_PRECAUTION_DELAY_META
        SIMULATION_CREATE_NODE(Node4);

        // Watcher, EXPERIMENTAL_PRECAUTION_DELAY_META
        SIMULATION_CREATE_NODE(Node5);

        SCPQuorumSet qSet;
        qSet.threshold = 3;
        qSet.validators.push_back(vNode1NodeID);
        qSet.validators.push_back(vNode2NodeID);
        qSet.validators.push_back(vNode3NodeID);

        Config const& cfg1 = getTestConfig(1);
        Config const& cfg2 = getTestConfig(2);
        Config const& cfg3 = getTestConfig(3);
        Config cfg4 = getTestConfig(4);
        Config cfg5 = getTestConfig(5);

        // Step 2: open writable files and pass them to configs 4 and 5
        // (watchers).
        cfg4.NODE_IS_VALIDATOR = false;
        cfg4.FORCE_SCP = false;
        cfg5.NODE_IS_VALIDATOR = false;
        cfg5.FORCE_SCP = false;
#ifdef _WIN32
        cfg4.METADATA_OUTPUT_STREAM = metaPath;
        cfg5.METADATA_OUTPUT_STREAM = metaPathSafe;
#else
        int fd = ::open(metaPath.c_str(), O_CREAT | O_WRONLY, 0644);
        REQUIRE(fd != -1);
        cfg4.METADATA_OUTPUT_STREAM = fmt::format(FMT_STRING("fd:{}"), fd);
        int fdSafe = ::open(metaPathSafe.c_str(), O_CREAT | O_WRONLY, 0644);
        REQUIRE(fdSafe != -1);
        cfg5.METADATA_OUTPUT_STREAM = fmt::format(FMT_STRING("fd:{}"), fdSafe);
#endif

        cfg4.EXPERIMENTAL_PRECAUTION_DELAY_META = false;
        cfg5.EXPERIMENTAL_PRECAUTION_DELAY_META = true;
        cfg5.setInMemoryMode(); // needed by EXPERIMENTAL_PRECAUTION_DELAY_META

        // Step 3: Run simulation a few steps to stream metadata.
        auto app1 = simulation->addNode(vNode1SecretKey, qSet, &cfg1);
        auto app2 = simulation->addNode(vNode2SecretKey, qSet, &cfg2);
        auto app3 = simulation->addNode(vNode3SecretKey, qSet, &cfg3);
        auto app4 = simulation->addNode(vNode4SecretKey, qSet, &cfg4);
        auto app5 = simulation->addNode(vNode5SecretKey, qSet, &cfg5);

        simulation->addPendingConnection(vNode1NodeID, vNode2NodeID);
        simulation->addPendingConnection(vNode1NodeID, vNode3NodeID);
        simulation->addPendingConnection(vNode1NodeID, vNode4NodeID);
        simulation->addPendingConnection(vNode1NodeID, vNode5NodeID);

        simulation->startAllNodes();
        bool watchersAreCorrupted = false;
        simulation->crankUntil(
            [&]() {
                // As long as the watchers are in sync, wait for them to get the
                // news of all the ledgers closed by the validators.  But once
                // the watchers are corrupt, they won't be able to close more
                // ledgers, so at that point we start waiting only for the
                // validators to do so.
                if (watchersAreCorrupted)
                {
                    return app1->getLedgerManager().getLastClosedLedgerNum() ==
                           ledgerToWaitFor;
                }

                auto const lastClosedLedger =
                    app4->getLedgerManager().getLastClosedLedgerNum();
                REQUIRE(app5->getLedgerManager().getLastClosedLedgerNum() ==
                        lastClosedLedger);

                if (lastClosedLedger == expectedLastWatcherLedger - 1)
                {
                    expectedLastSafeHash = app5->getLedgerManager()
                                               .getLastClosedLedgerHeader()
                                               .hash;

                    if (induceOneLedgerFork)
                    {
                        for (auto& app : {app4, app5})
                        {
                            txtest::closeLedgerOn(
                                *app, ledgerToCorrupt,
                                app->getLedgerManager()
                                        .getLastClosedLedgerHeader()
                                        .header.scpValue.closeTime +
                                    1);
                        }

                        expectedLastUnsafeHash =
                            app4->getLedgerManager()
                                .getLastClosedLedgerHeader()
                                .hash;

                        watchersAreCorrupted = true;
                        return false;
                    }
                }

                return lastClosedLedger == ledgerToWaitFor;
            },
            std::chrono::seconds{200}, false);

        REQUIRE(app4->getLedgerManager().getLastClosedLedgerNum() ==
                expectedLastWatcherLedger);
        REQUIRE(app5->getLedgerManager().getLastClosedLedgerNum() ==
                expectedLastWatcherLedger);

        if (!induceOneLedgerFork)
        {
            expectedLastUnsafeHash =
                app4->getLedgerManager().getLastClosedLedgerHeader().hash;
        }
    }

    // Step 4: reopen the files as XDR streams and read back the LCMs
    // and check they have the expected content.
    auto readLcms = [](std::string const& lcmPath) {
        std::vector<LedgerCloseMeta> lcms;
        XDRInputFileStream stream;
        stream.open(lcmPath);
        LedgerCloseMeta lcm;
        while (stream && stream.readOne(lcm))
        {
            lcms.push_back(lcm);
        }
        return lcms;
    };

    auto lcms = readLcms(metaPath);
    auto lcmsSafe = readLcms(metaPathSafe);
    // The "- 1" is because we don't stream meta for the genesis ledger.
    REQUIRE(lcms.size() == expectedLastWatcherLedger - 1);
    if (lcms.back().v() == 0)
    {
        REQUIRE(lcms.back().v0().ledgerHeader.hash == expectedLastUnsafeHash);
    }
    else if (lcms.back().v() == 1)
    {
        REQUIRE(lcms.back().v1().ledgerHeader.hash == expectedLastUnsafeHash);
    }
    else
    {
#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
        REQUIRE(lcms.back().v2().ledgerHeader.hash == expectedLastUnsafeHash);
#else
        REQUIRE(false);
#endif
    }

    // The node with EXPERIMENTAL_PRECAUTION_DELAY_META should not have streamed
    // the meta for the latest ledger (or the latest ledger before the corrupt
    // one) yet.
    REQUIRE(lcmsSafe.size() == lcms.size() - 1);

    if (lcmsSafe.back().v() == 0)
    {
        REQUIRE(lcmsSafe.back().v0().ledgerHeader.hash == expectedLastSafeHash);
    }
    else if (lcmsSafe.back().v() == 1)
    {
        REQUIRE(lcmsSafe.back().v1().ledgerHeader.hash == expectedLastSafeHash);
    }
#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
    else
    {
        REQUIRE(lcmsSafe.back().v2().ledgerHeader.hash == expectedLastSafeHash);
    }
#endif
    REQUIRE(lcmsSafe ==
            std::vector<LedgerCloseMeta>(lcms.begin(), lcms.end() - 1));
}

TEST_CASE("LedgerCloseMetaStream file descriptor - REPLAY_IN_MEMORY",
          "[ledgerclosemetastreamreplay]")
{
    // Step 1: generate some history for replay.
    using namespace stellar::historytestutils;
    TmpDirHistoryConfigurator tCfg;
    {
        Config genCfg = getTestConfig(0, Config::TESTDB_DEFAULT);
        genCfg.MANUAL_CLOSE = false;
        VirtualClock genClock;
        genCfg = tCfg.configure(genCfg, true);
        auto genApp = createTestApplication(genClock, genCfg);
        auto& genHam = genApp->getHistoryArchiveManager();
        genHam.initializeHistoryArchive(tCfg.getArchiveDirName());
        for (size_t i = 0; i < 100; ++i)
        {
            genClock.crank(false);
        }
        auto& genHm = genApp->getHistoryManager();
        while (genHm.getPublishSuccessCount() < 5)
        {
            genClock.crank(true);
        }
        while (genClock.cancelAllEvents() ||
               genApp->getProcessManager().getNumRunningProcesses() > 0)
        {
            genClock.crank(false);
        }
    }

    // Step 2: open a writable file descriptor.
    TmpDirManager tdm(std::string("streamtmp-") + binToHex(randomBytes(8)));
    TmpDir td = tdm.tmpDir("streams");
    std::string metaPath = td.getName() + "/stream.xdr";
    auto cfg1 = getTestConfig(1);
#ifdef _WIN32
    cfg1.METADATA_OUTPUT_STREAM = metaPath;
#else
    int fd = ::open(metaPath.c_str(), O_CREAT | O_WRONLY, 0644);
    REQUIRE(fd != -1);
    cfg1.METADATA_OUTPUT_STREAM = fmt::format(FMT_STRING("fd:{}"), fd);
#endif

    bool const delayMeta = GENERATE(true, false);

    // Step 3: pass it to an application and have it catch up to the generated
    // history, streaming ledgerCloseMeta to the file descriptor.
    Hash hash;
    {
        auto cfg = tCfg.configure(cfg1, false);
        cfg.NODE_IS_VALIDATOR = false;
        cfg.FORCE_SCP = false;
        cfg.RUN_STANDALONE = true;
        cfg.setInMemoryMode();
        cfg.EXPERIMENTAL_PRECAUTION_DELAY_META = delayMeta;
        VirtualClock clock;
        auto app = createTestApplication(clock, cfg, /*newdb=*/false);

        CatchupConfiguration cc{CatchupConfiguration::CURRENT,
                                std::numeric_limits<uint32_t>::max(),
                                CatchupConfiguration::Mode::OFFLINE_COMPLETE};
        Json::Value catchupInfo;
        auto& ham = app->getHistoryArchiveManager();
        auto& lm = app->getLedgerManager();
        auto archive = ham.selectRandomReadableHistoryArchive();
        int res = catchup(app, cc, catchupInfo, archive);
        REQUIRE(res == 0);
        hash = lm.getLastClosedLedgerHeader().hash;
        while (clock.cancelAllEvents() ||
               app->getProcessManager().getNumRunningProcesses() > 0)
        {
            clock.crank(false);
        }
    }

    // Step 4: reopen the file as an XDR stream and read back the LCMs
    // and check they have the expected content.
    //
    // The EXPERIMENTAL_PRECAUTION_DELAY_META case should still have streamed
    // the latest meta, because catchup should have validated that ledger's hash
    // by validating a chain of hashes back from one obtained from consensus.
    XDRInputFileStream stream;
    stream.open(metaPath);
    LedgerCloseMeta lcm;
    size_t nLcm = 1;
    while (stream && stream.readOne(lcm))
    {
        ++nLcm;
    }
    // 5 checkpoints is ledger 0x13f
    REQUIRE(nLcm == 0x13f);
    if (lcm.v() == 0)
    {
        REQUIRE(lcm.v0().ledgerHeader.hash == hash);
    }
    else if (lcm.v() == 1)
    {
        REQUIRE(lcm.v1().ledgerHeader.hash == hash);
    }
    else
    {
#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
        REQUIRE(lcm.v2().ledgerHeader.hash == hash);
#else
        REQUIRE(false);
#endif
    }
}

TEST_CASE("EXPERIMENTAL_PRECAUTION_DELAY_META configuration",
          "[ledgerclosemetastreamlive][ledgerclosemetastreamreplay]")
{
    VirtualClock clock;
    Config cfg = getTestConfig();

    SECTION("EXPERIMENTAL_PRECAUTION_DELAY_META may take either value "
            "(which is ignored) without METADATA_OUTPUT_STREAM")
    {
        cfg.METADATA_OUTPUT_STREAM = "";
        auto const delayMeta = GENERATE(false, true);
        auto const inMemory = GENERATE(false, true);
        cfg.EXPERIMENTAL_PRECAUTION_DELAY_META = delayMeta;
        if (inMemory)
        {
            cfg.setInMemoryMode();
        }
        REQUIRE_NOTHROW(createTestApplication(clock, cfg));
    }

    SECTION("EXPERIMENTAL_PRECAUTION_DELAY_META together with "
            "METADATA_OUTPUT_STREAM requires --in-memory")
    {
        TmpDirManager tdm(std::string("streamtmp-") + binToHex(randomBytes(8)));
        TmpDir td = tdm.tmpDir("streams");
        std::string metaPath = td.getName() + "/stream.xdr";
        std::string metaStream;

#ifdef _WIN32
        metaStream = metaPath;
#else
        int fd = ::open(metaPath.c_str(), O_CREAT | O_WRONLY, 0644);
        REQUIRE(fd != -1);
        metaStream = fmt::format(FMT_STRING("fd:{}"), fd);
#endif

        cfg.METADATA_OUTPUT_STREAM = metaStream;
        auto const delayMeta = GENERATE(false, true);
        auto const inMemory = GENERATE(false, true);
        cfg.EXPERIMENTAL_PRECAUTION_DELAY_META = delayMeta;
        if (inMemory)
        {
            cfg.setInMemoryMode();
        }
        if (delayMeta && !inMemory)
        {
            REQUIRE_THROWS_AS(createTestApplication(clock, cfg),
                              std::invalid_argument);
        }
        else
        {
            REQUIRE_NOTHROW(createTestApplication(clock, cfg));
        }
    }
}

TEST_CASE("METADATA_DEBUG_LEDGERS works", "[metadebug]")
{
    VirtualClock clock;
    Config cfg = getTestConfig();
    cfg.MANUAL_CLOSE = false;
    cfg.METADATA_DEBUG_LEDGERS = 768;
    auto app = createTestApplication(clock, cfg);
    app->start();
    auto bucketDir = app->getBucketManager().getBucketDir();
    auto n = FlushAndRotateMetaDebugWork::getNumberOfDebugFilesToKeep(
        cfg.METADATA_DEBUG_LEDGERS);
    bool gotToExpectedSize = false;
    auto& lm = app->getLedgerManager();
    while (lm.getLastClosedLedgerNum() < (2 * cfg.METADATA_DEBUG_LEDGERS))
    {
        clock.crank(false);
        if (app->getWorkScheduler().allChildrenDone() &&
            lm.getLastClosedLedgerNum() >= cfg.METADATA_DEBUG_LEDGERS)
        {
            auto files =
                FlushAndRotateMetaDebugWork::listMetaDebugFiles(bucketDir);
            REQUIRE(files.size() <= n);
            if (files.size() == n)
            {
                gotToExpectedSize = true;
            }
        }
    }
    while (!app->getWorkScheduler().allChildrenDone())
    {
        clock.crank(false);
    }
    REQUIRE(gotToExpectedSize);
}

TEST_CASE_VERSIONS("meta stream contains reasonable meta", "[ledgerclosemeta]")
{
    Config cfg = getTestConfig();

    // We need to fix a deterministic NODE_SEED for this test to be stable.
    cfg.NODE_SEED = SecretKey::pseudoRandomForTestingFromSeed(12345);

    TmpDirManager tdm(std::string("metatest-") + binToHex(randomBytes(8)));
    TmpDir td = tdm.tmpDir("meta-ok");
    std::string metaPath = td.getName() + "/stream.xdr";

    VirtualClock clock;
    cfg.METADATA_OUTPUT_STREAM = metaPath;

    {
        // Do some stuff
        using namespace stellar::txtest;
        auto app = createTestApplication(clock, cfg);
        auto& lm = app->getLedgerManager();
        auto txFee = lm.getLastTxFee();
        auto bal = app->getLedgerManager().getLastMinBalance(2);

        auto root = TestAccount::createRoot(*app);

        // Ledgers #2, #3 and #4 create accounts, which happen directly and
        // don't emit meta.
        auto acc1 = root.create("acc1", bal);
        auto acc2 = root.create("acc2", bal);
        auto issuer =
            root.create("issuer", lm.getLastMinBalance(0) + 100 * txFee);
        auto cur1 = issuer.asset("CUR1");

        // Ledger #5 sets up a trustline which has to happen before we can use
        // it.
        acc1.changeTrust(cur1, 100);

        // Ledger #6 uses closeLedger so emits interesting meta.
        std::vector<TransactionFrameBasePtr> txs = {
            // First tx pays 1000 XLM from root to acc1
            root.tx({payment(acc1.getPublicKey(), 1000)}),
            // Second tx pays acc1 50 cur1 units twice from issuer.
            issuer.tx({payment(acc1, cur1, 50), payment(acc1, cur1, 50)})};
        if (protocolVersionStartsFrom(
                cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION,
                ProtocolVersion::V_13))
        {
            // If we're in the world where fee-bumps exist (protocol 13 or
            // later), we re-wrap the final tx in a fee-bump from acc2.
            auto tx = txs.back();
            txs.back() = feeBump(*app, acc2, tx, 5000);
        }
        closeLedger(*app, txs);
    }

    // We're going to examine the meta generated by ledger #6.
    uint32_t const targetSeq = 6;

    XDRInputFileStream in;
    in.open(metaPath);
    LedgerCloseMeta lcm;
    uint32_t maxSeq = 0;
    while (in.readOne(lcm))
    {
        uint32_t ledgerSeq{0};

        if (protocolVersionIsBefore(cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION,
                                    GENERALIZED_TX_SET_PROTOCOL_VERSION))
        {
            // LCM v0
            REQUIRE(lcm.v() == 0);
            REQUIRE(lcm.v0().ledgerHeader.header.ledgerVersion ==
                    cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION);
            ledgerSeq = lcm.v0().ledgerHeader.header.ledgerSeq;
        }
#ifdef ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
        else if (protocolVersionStartsFrom(
                     cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION,
                     SOROBAN_PROTOCOL_VERSION))
        {
            // LCM v2
            REQUIRE(lcm.v() == 2);
            REQUIRE(lcm.v2().ledgerHeader.header.ledgerVersion ==
                    cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION);
            ledgerSeq = lcm.v2().ledgerHeader.header.ledgerSeq;
        }
#endif
        else
        {
            // LCM v1
            REQUIRE(lcm.v() == 1);
            REQUIRE(lcm.v1().ledgerHeader.header.ledgerVersion ==
                    cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION);
            ledgerSeq = lcm.v1().ledgerHeader.header.ledgerSeq;
        }

        if (ledgerSeq == targetSeq)
        {
            std::string refJsonPath = fmt::format(
                FMT_STRING("testdata/ledger-close-meta-v{}-protocol-{}.json"),
                lcm.v(), cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION);
            std::string have = xdr_to_string(lcm, "LedgerCloseMeta");
            if (getenv("GENERATE_TEST_LEDGER_CLOSE_META"))
            {
                std::ofstream outJson(refJsonPath);
                outJson.write(have.data(), have.size());
            }
            else
            {
                std::ifstream inJson(refJsonPath);
                REQUIRE(inJson);
                std::string expect(std::istreambuf_iterator<char>{inJson}, {});
                REQUIRE(expect == have);
            }
        }
        maxSeq = ledgerSeq;
    }
    REQUIRE(maxSeq == targetSeq);
}
