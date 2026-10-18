"use strict";

const { expect } = require("chai");
const pth = require("path");
const fs = require("fs");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Constants = require("../util/constants");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Deterministic variant of the RSS checks above: a lazily committed, zero-filled
// allocation does not necessarily show up in RSS, so record every Buffer.alloc
// request made while an entry is read and refuse anything anywhere near the
// declared size. The vulnerable code path then fails fast instead of committing
// gigabytes, and the assertion names the size it tried to allocate.
describe("decompression bomb (declared size) - CVE-2026-39244 allocation guard", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024;
    const ALLOC_LIMIT = 64 * 1024 * 1024;
    const destination = pth.join(__dirname, "xxx_decompress_bomb");

    // runs fn with Buffer.alloc instrumented, returns the largest size requested
    function largestAllocDuring(fn) {
        const original = Buffer.alloc;
        let largest = 0;
        Buffer.alloc = function (size) {
            if (size > largest) largest = size;
            if (size > ALLOC_LIMIT) {
                throw new Error("refusing to allocate " + size + " bytes");
            }
            return original.apply(this, arguments);
        };
        try {
            fn();
        } finally {
            Buffer.alloc = original;
        }
        return largest;
    }

    function storedBomb() {
        return new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
    }

    function deflatedBomb() {
        return new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
    }

    after((done) => rimraf(destination, done));

    it("getData() never allocates the declared size of a STORED entry", () => {
        const entry = storedBomb().getEntries()[0];
        let thrown;
        const largest = largestAllocDuring(() => {
            try {
                entry.getData();
            } catch (e) {
                thrown = e;
            }
        });
        expect(largest, "largest Buffer.alloc request").to.be.below(ALLOC_LIMIT);
        expect(thrown).to.be.an("error");
        expect(thrown.message).to.match(/CRC32/);
    });

    it("getData() never allocates the declared size of a DEFLATED entry", () => {
        const entry = deflatedBomb().getEntries()[0];
        let thrown;
        const largest = largestAllocDuring(() => {
            try {
                entry.getData();
            } catch (e) {
                thrown = e;
            }
        });
        expect(largest, "largest Buffer.alloc request").to.be.below(ALLOC_LIMIT);
        expect(thrown).to.be.an("error");
        expect(thrown.message).to.not.match(/refusing to allocate/);
    });

    it("getDataAsync() never allocates the declared size of a STORED entry", () => {
        const entry = storedBomb().getEntries()[0];
        let cbError;
        const largest = largestAllocDuring(() => {
            try {
                entry.getDataAsync((data, err) => {
                    cbError = err;
                });
            } catch (e) {
                // the STORED async path reports the CRC failure through the callback and throws
            }
        });
        expect(largest, "largest Buffer.alloc request").to.be.below(ALLOC_LIMIT);
        expect(cbError).to.be.an("error");
        expect(cbError.message).to.match(/CRC32/);
    });

    it("getDataAsync() never allocates the declared size of a DEFLATED entry", (done) => {
        const entry = deflatedBomb().getEntries()[0];
        // the output buffer used to be allocated synchronously, before inflating starts
        const largest = largestAllocDuring(() => {
            entry.getDataAsync((data, err) => {
                try {
                    expect(err).to.be.an("error");
                    expect(data.length).to.equal(0);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });
        expect(largest, "largest Buffer.alloc request").to.be.below(ALLOC_LIMIT);
    });

    it("readFile() and test() never allocate the declared size", () => {
        const stored = storedBomb();
        const deflated = deflatedBomb();
        let tested;
        const largest = largestAllocDuring(() => {
            expect(() => stored.readFile("a")).to.throw(/CRC32/);
            expect(() => deflated.readFile("a")).to.throw();
            tested = [stored.test(), deflated.test()];
        });
        expect(largest, "largest Buffer.alloc request").to.be.below(ALLOC_LIMIT);
        expect(tested).to.eql([false, false]);
    });

    it("extractAllTo() never allocates the declared size and writes nothing", () => {
        const zip = storedBomb();
        let thrown;
        const largest = largestAllocDuring(() => {
            try {
                zip.extractAllTo(destination, true);
            } catch (e) {
                thrown = e;
            }
        });
        expect(largest, "largest Buffer.alloc request").to.be.below(ALLOC_LIMIT);
        expect(thrown).to.be.an("error");
        expect(thrown.message).to.match(/CRC32/);
        expect(fs.existsSync(pth.join(destination, "a"))).to.equal(false);
    });

    it("never returns more data than a DEFLATED entry declares (sync, every node version)", () => {
        // a valid deflate stream with a valid CRC whose declared uncompressed size
        // understates the real one; dropping the pre-allocation must not let the
        // full output through on runtimes where zlib ignores maxOutputLength
        const payload = Buffer.alloc(64 * 1024, 0x61);
        const zip = new Zip();
        zip.addFile("u.bin", payload);
        const buf = Buffer.from(zip.toBuffer());

        expect(buf.readUInt32LE(0)).to.equal(Constants.LOCSIG);
        expect(buf.readUInt16LE(Constants.LOCHOW)).to.equal(Constants.DEFLATED);
        buf.writeUInt32LE(16, Constants.LOCLEN);
        const endOffset = buf.length - Constants.ENDHDR;
        const cenOffset = buf.readUInt32LE(endOffset + Constants.ENDOFF);
        expect(buf.readUInt32LE(cenOffset)).to.equal(Constants.CENSIG);
        buf.writeUInt32LE(16, cenOffset + Constants.CENLEN);

        expect(() => new Zip(buf).readFile("u.bin")).to.throw(RangeError);
    });
});
