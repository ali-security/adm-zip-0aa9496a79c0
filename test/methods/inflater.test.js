"use strict";

// Decompression-bomb regression tests: the inflater must never produce more output
// than the entry's declared uncompressed size, on both the sync and async paths,
// and a declared size of 0 must not disable that cap.

const { expect } = require("chai");
const pth = require("path");
const fs = require("fs");
const zlib = require("zlib");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");
const Inflater = require("../../methods/inflater");
const Constants = require("../../util/constants");

const nodeMajor = +(process.versions ? process.versions.node : "").split(".")[0] || 0;
// zlib only honours maxOutputLength for the synchronous convenience methods, and the
// inflater only passes it on node >= 15
const syncCapSupported = nodeMajor >= 15;

// 1 MiB of zeros deflates to roughly 1 KiB: a ~1000:1 amplification payload
const BOMB_SIZE = 1024 * 1024;
const BOMB_NAME = "bomb.bin";
const bombPlain = Buffer.alloc(BOMB_SIZE, 0);
const bombDeflated = zlib.deflateRawSync(bombPlain);

// Builds a single-entry archive holding the bomb and rewrites the declared
// uncompressed size in both the local and the central directory header, keeping
// the (valid) CRC32 untouched - exactly what an attacker would do.
function bombZipDeclaring(size) {
    const zip = new Zip();
    zip.addFile(BOMB_NAME, bombPlain);
    const buf = Buffer.from(zip.toBuffer());

    // single entry archive without a comment: LOC at offset 0, END at the very end
    expect(buf.readUInt32LE(0)).to.equal(Constants.LOCSIG);
    expect(buf.readUInt16LE(Constants.LOCHOW)).to.equal(Constants.DEFLATED);
    buf.writeUInt32LE(size, Constants.LOCLEN);

    const endOffset = buf.length - Constants.ENDHDR;
    expect(buf.readUInt32LE(endOffset)).to.equal(Constants.ENDSIG);
    const cenOffset = buf.readUInt32LE(endOffset + Constants.ENDOFF);
    expect(buf.readUInt32LE(cenOffset)).to.equal(Constants.CENSIG);
    buf.writeUInt32LE(size, cenOffset + Constants.CENLEN);

    return buf;
}

// runs the assertions of an async callback and routes failures to mocha's done()
function check(done, assertions) {
    try {
        assertions();
        done();
    } catch (e) {
        done(e);
    }
}

describe("methods/inflater.js - decompression size cap", () => {
    it("sanity: the payload really is highly compressed", () => {
        expect(bombDeflated.length).to.be.below(BOMB_SIZE / 100);
    });

    describe("inflate() (sync)", () => {
        it("inflates an entry whose declared size matches its content", () => {
            const out = new Inflater(bombDeflated, BOMB_SIZE).inflate();
            expect(out.length).to.equal(BOMB_SIZE);
            expect(out.equals(bombPlain)).to.equal(true);
        });

        it("still inflates a genuinely empty entry declared with size 0", () => {
            const empty = zlib.deflateRawSync(Buffer.alloc(0));
            expect(empty.length).to.be.above(0);
            const out = new Inflater(empty, 0).inflate();
            expect(out.length).to.equal(0);
        });

        it("refuses to inflate a bomb that declares an uncompressed size of 0", function () {
            if (!syncCapSupported) this.skip();
            expect(() => new Inflater(bombDeflated, 0).inflate()).to.throw(RangeError);
        });

        it("refuses to inflate a bomb that understates its uncompressed size", function () {
            if (!syncCapSupported) this.skip();
            expect(() => new Inflater(bombDeflated, 1024).inflate()).to.throw(RangeError);
        });
    });

    describe("inflateAsync()", () => {
        it("inflates an entry whose declared size matches its content", (done) => {
            new Inflater(bombDeflated, BOMB_SIZE).inflateAsync((data, err) => {
                check(done, () => {
                    expect(err).to.equal(undefined);
                    expect(data.length).to.equal(BOMB_SIZE);
                    expect(data.equals(bombPlain)).to.equal(true);
                });
            });
        });

        it("still inflates a genuinely empty entry declared with size 0", (done) => {
            const empty = zlib.deflateRawSync(Buffer.alloc(0));
            new Inflater(empty, 0).inflateAsync((data, err) => {
                check(done, () => {
                    expect(err).to.equal(undefined);
                    expect(data.length).to.equal(0);
                });
            });
        });

        it("rejects a bomb that declares an uncompressed size of 0", (done) => {
            new Inflater(bombDeflated, 0).inflateAsync((data, err) => {
                check(done, () => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.contain("exceeds the declared uncompressed size");
                    expect(data.length).to.equal(0);
                });
            });
        });

        it("rejects a bomb that understates its uncompressed size", (done) => {
            new Inflater(bombDeflated, 1024).inflateAsync((data, err) => {
                check(done, () => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.contain("exceeds the declared uncompressed size");
                    expect(data.length).to.equal(0);
                });
            });
        });

        it("invokes the callback exactly once when the cap is exceeded", (done) => {
            let calls = 0;
            new Inflater(bombDeflated, 1).inflateAsync(() => {
                calls++;
                if (calls === 1) {
                    // give the (destroyed) stream a chance to emit anything else
                    setTimeout(() => check(done, () => expect(calls).to.equal(1)), 100);
                }
            });
        });

        it("reports malformed deflate data through the callback instead of crashing", (done) => {
            // BFINAL=1 with the reserved block type 3: zlib fails with Z_DATA_ERROR
            const garbage = Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
            new Inflater(garbage, 100).inflateAsync((data, err) => {
                check(done, () => {
                    expect(err).to.be.an("error");
                    expect(data.length).to.equal(0);
                });
            });
        });
    });
});

describe("adm-zip.js - decompression bomb entries", () => {
    const destination = pth.join(__dirname, "xxx");

    afterEach((done) => rimraf(destination, done));

    it("reads an entry whose declared size is honest (sync and async)", (done) => {
        const zip = new Zip(bombZipDeclaring(BOMB_SIZE));
        expect(zip.readFile(BOMB_NAME).equals(bombPlain)).to.equal(true);
        zip.readFileAsync(BOMB_NAME, (data, err) => {
            check(done, () => {
                expect(err).to.equal(undefined);
                expect(data.equals(bombPlain)).to.equal(true);
            });
        });
    });

    it("readFile() refuses an entry declaring size 0 that inflates to more", function () {
        if (!syncCapSupported) this.skip();
        const zip = new Zip(bombZipDeclaring(0));
        expect(() => zip.readFile(BOMB_NAME)).to.throw(RangeError);
    });

    it("readFileAsync() reports an error for an entry declaring size 0", (done) => {
        const zip = new Zip(bombZipDeclaring(0));
        zip.readFileAsync(BOMB_NAME, (data, err) => {
            check(done, () => {
                expect(err).to.be.an("error");
                expect(err.message).to.contain("exceeds the declared uncompressed size");
                expect(data.length).to.equal(0);
            });
        });
    });

    it("ZipEntry.getDataAsync() reports an error for an entry understating its size", (done) => {
        const zip = new Zip(bombZipDeclaring(1));
        zip.getEntry(BOMB_NAME).getDataAsync((data, err) => {
            check(done, () => {
                expect(err).to.be.an("error");
                expect(err.message).to.contain("exceeds the declared uncompressed size");
                expect(data.length).to.equal(0);
            });
        });
    });

    it("readAsTextAsync() reports an error for an entry declaring size 0", (done) => {
        const zip = new Zip(bombZipDeclaring(0));
        zip.readAsTextAsync(BOMB_NAME, (data, err) => {
            check(done, () => {
                expect(err).to.be.an("error");
                expect(err.message).to.contain("exceeds the declared uncompressed size");
            });
        });
    });

    it("extractAllToAsync() fails and does not write a bomb declaring size 0", (done) => {
        const zip = new Zip(bombZipDeclaring(0));
        zip.extractAllToAsync(destination, true, false, (err) => {
            check(done, () => {
                expect(err).to.be.an("error");
                expect(err.message).to.contain("exceeds the declared uncompressed size");
                expect(fs.existsSync(pth.join(destination, BOMB_NAME))).to.equal(false);
            });
        });
    });
});
