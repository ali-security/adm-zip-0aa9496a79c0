"use strict";
const { expect } = require("chai");
const fs = require("fs");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util/utils");

const isWin = process.platform === "win32";

// Extraction must never write through a symlink that already exists inside the
// target folder: sanitize() only validates the textual path, while open()/mkdir()
// follow a planted link and would land outside the target folder.
describe("extraction through pre-existing symlinks", () => {
    const base = pth.resolve(__dirname, "xxx_symlink");
    const out = pth.join(base, "out");
    const outside = pth.join(base, "outside");
    let links = [];

    // directory links use junctions on Windows so no elevated rights are needed
    function linkDir(target, link) {
        fs.symlinkSync(pth.resolve(target), link, isWin ? "junction" : "dir");
        links.push(link);
    }

    // file links need symlink privileges on Windows; report whether it worked
    function linkFile(target, link) {
        try {
            fs.symlinkSync(pth.resolve(target), link, "file");
        } catch (e) {
            if (isWin && e.code === "EPERM") return false;
            throw e;
        }
        links.push(link);
        return true;
    }

    function unlinkAll() {
        // remove the links themselves first so cleanup never follows them
        links.forEach((link) => {
            try {
                fs.unlinkSync(link);
            } catch (e) {
                try {
                    fs.rmdirSync(link);
                } catch (e2) {
                    /* already gone */
                }
            }
        });
        links = [];
    }

    function makeZip(entries) {
        const zip = new Zip();
        entries.forEach((name) => zip.addFile(name, name.endsWith("/") ? null : Buffer.from("pwned")));
        return new Zip(zip.toBuffer());
    }

    function list(dir) {
        return fs.existsSync(dir) ? fs.readdirSync(dir).sort() : [];
    }

    beforeEach(() => {
        unlinkAll();
        rimraf.sync(base);
        fs.mkdirSync(out, { recursive: true });
        fs.mkdirSync(outside, { recursive: true });
    });

    afterEach(() => {
        unlinkAll();
        rimraf.sync(base);
    });

    describe("Utils.assertPathSafe()", () => {
        const tools = new Utils();

        it("rejects a target whose parent component is a symlink", () => {
            linkDir(outside, pth.join(out, "link"));
            expect(() => tools.assertPathSafe(out, pth.join(out, "link", "evil.txt"))).to.throw(/file in the way/);
        });

        it("rejects a target that is itself a symlink", () => {
            linkDir(outside, pth.join(out, "link"));
            expect(() => tools.assertPathSafe(out, pth.join(out, "link"))).to.throw(/file in the way/);
        });

        it("rejects a symlink nested below a real folder", () => {
            fs.mkdirSync(pth.join(out, "a"));
            linkDir(outside, pth.join(out, "a", "b"));
            expect(() => tools.assertPathSafe(out, pth.join(out, "a", "b", "c", "evil.txt"))).to.throw(/file in the way/);
        });

        it("accepts real and not-yet-existing paths", () => {
            fs.mkdirSync(pth.join(out, "a"));
            fs.writeFileSync(pth.join(out, "a", "file.txt"), "x");
            expect(() => tools.assertPathSafe(out, out)).to.not.throw();
            expect(() => tools.assertPathSafe(out, pth.join(out, "a", "file.txt"))).to.not.throw();
            expect(() => tools.assertPathSafe(out, pth.join(out, "a", "new", "deep", "file.txt"))).to.not.throw();
        });

        it("ignores symlinks at or above the target folder", () => {
            const rootLink = pth.join(base, "rootlink");
            linkDir(out, rootLink);
            expect(() => tools.assertPathSafe(rootLink, pth.join(rootLink, "file.txt"))).to.not.throw();
        });

        it("is a no-op for a custom fs without lstatSync", () => {
            linkDir(outside, pth.join(out, "link"));
            const custom = new Utils({ fs: { statSync: fs.statSync } });
            expect(() => custom.assertPathSafe(out, pth.join(out, "link", "evil.txt"))).to.not.throw();
        });
    });

    describe("extractAllTo()", () => {
        it("refuses to write a file through a symlinked folder", () => {
            linkDir(outside, pth.join(out, "link"));
            const zip = makeZip(["link/evil.txt"]);

            expect(() => zip.extractAllTo(out)).to.throw(/file in the way/);
            expect(list(outside)).to.deep.equal([]);
        });

        it("refuses to create a folder through a symlinked folder", () => {
            linkDir(outside, pth.join(out, "link"));
            const zip = makeZip(["link/sub/"]);

            expect(() => zip.extractAllTo(out)).to.throw(/file in the way/);
            expect(list(outside)).to.deep.equal([]);
        });

        it("refuses to write through a symlink nested below a real folder", () => {
            fs.mkdirSync(pth.join(out, "a"));
            linkDir(outside, pth.join(out, "a", "b"));
            const zip = makeZip(["a/b/c/evil.txt"]);

            expect(() => zip.extractAllTo(out, true)).to.throw(/file in the way/);
            expect(list(outside)).to.deep.equal([]);
        });

        it("refuses to overwrite a file through a symlinked file", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "original");
            if (!linkFile(secret, pth.join(out, "victim.txt"))) this.skip();
            const zip = makeZip(["victim.txt"]);

            expect(() => zip.extractAllTo(out, true)).to.throw(/file in the way/);
            expect(fs.readFileSync(secret, "utf8")).to.equal("original");
        });

        it("still extracts into a target folder that is itself a symlink", () => {
            const realOut = pth.join(base, "real");
            fs.mkdirSync(realOut);
            const rootLink = pth.join(base, "rootlink");
            linkDir(realOut, rootLink);
            const zip = makeZip(["dir/", "dir/file.txt", "top.txt"]);

            zip.extractAllTo(rootLink);
            zip.extractAllTo(rootLink, true);
            expect(fs.readFileSync(pth.join(realOut, "dir", "file.txt"), "utf8")).to.equal("pwned");
            expect(fs.readFileSync(pth.join(realOut, "top.txt"), "utf8")).to.equal("pwned");
        });
    });

    describe("extractEntryTo()", () => {
        it("refuses to write a file entry through a symlinked folder", () => {
            linkDir(outside, pth.join(out, "link"));
            const zip = makeZip(["link/evil.txt"]);

            expect(() => zip.extractEntryTo("link/evil.txt", out, true, true)).to.throw(/file in the way/);
            expect(list(outside)).to.deep.equal([]);
        });

        it("refuses to write a directory entry's children through a symlinked folder", () => {
            linkDir(outside, pth.join(out, "link"));
            const zip = makeZip(["link/", "link/evil.txt"]);

            expect(() => zip.extractEntryTo("link/", out, true, true)).to.throw(/file in the way/);
            expect(list(outside)).to.deep.equal([]);
        });

        it("refuses to write through a symlinked folder named by outFileName", () => {
            linkDir(outside, pth.join(out, "link"));
            const zip = makeZip(["safe.txt"]);

            expect(() => zip.extractEntryTo("safe.txt", out, true, true, false, "link/evil.txt")).to.throw(/file in the way/);
            expect(list(outside)).to.deep.equal([]);
        });

        it("refuses to overwrite a file through a symlinked file", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "original");
            if (!linkFile(secret, pth.join(out, "victim.txt"))) this.skip();
            const zip = makeZip(["victim.txt"]);

            expect(() => zip.extractEntryTo("victim.txt", out, true, true)).to.throw(/file in the way/);
            expect(fs.readFileSync(secret, "utf8")).to.equal("original");
        });

        it("still extracts regular entries", () => {
            const zip = makeZip(["dir/", "dir/file.txt"]);

            expect(zip.extractEntryTo("dir/file.txt", out, true, false)).to.equal(true);
            expect(zip.extractEntryTo("dir/", out, false, true)).to.equal(true);
            expect(fs.readFileSync(pth.join(out, "dir", "file.txt"), "utf8")).to.equal("pwned");
            expect(fs.readFileSync(pth.join(out, "file.txt"), "utf8")).to.equal("pwned");
        });
    });

    describe("extractAllToAsync()", () => {
        it("refuses to write a file through a symlinked folder (callback)", (done) => {
            linkDir(outside, pth.join(out, "link"));
            const zip = makeZip(["link/evil.txt"]);

            zip.extractAllToAsync(out, false, false, (err) => {
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(/file in the way/);
                    expect(list(outside)).to.deep.equal([]);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("refuses to write a file through a symlinked folder (promise)", () => {
            linkDir(outside, pth.join(out, "link"));
            const zip = makeZip(["link/evil.txt"]);

            return zip.extractAllToAsync(out, true).then(
                () => {
                    throw new Error("extraction through a symlink must fail");
                },
                (err) => {
                    expect(err.message).to.match(/file in the way/);
                    expect(list(outside)).to.deep.equal([]);
                }
            );
        });

        it("refuses to create a folder through a symlinked folder", () => {
            linkDir(outside, pth.join(out, "link"));
            const zip = makeZip(["link/sub/"]);

            return zip.extractAllToAsync(out).then(
                () => {
                    throw new Error("extraction through a symlink must fail");
                },
                (err) => {
                    expect(err.message).to.match(/Unable to create folder/);
                    expect(list(outside)).to.deep.equal([]);
                }
            );
        });

        it("refuses to overwrite a file through a symlinked file", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "original");
            if (!linkFile(secret, pth.join(out, "victim.txt"))) this.skip();
            const zip = makeZip(["victim.txt"]);

            return zip.extractAllToAsync(out, true).then(
                () => {
                    throw new Error("extraction through a symlink must fail");
                },
                (err) => {
                    expect(err.message).to.match(/file in the way/);
                    expect(fs.readFileSync(secret, "utf8")).to.equal("original");
                }
            );
        });

        it("still extracts into a target folder that is itself a symlink", () => {
            const realOut = pth.join(base, "real");
            fs.mkdirSync(realOut);
            const rootLink = pth.join(base, "rootlink");
            linkDir(realOut, rootLink);
            const zip = makeZip(["dir/", "dir/file.txt", "top.txt"]);

            return zip.extractAllToAsync(rootLink, true).then(() => {
                expect(fs.readFileSync(pth.join(realOut, "dir", "file.txt"), "utf8")).to.equal("pwned");
                expect(fs.readFileSync(pth.join(realOut, "top.txt"), "utf8")).to.equal("pwned");
            });
        });
    });
});
