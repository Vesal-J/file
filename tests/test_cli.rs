// This file is part of the uutils file package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

use std::sync::atomic::{AtomicBool, Ordering};
use uutests::util::{TestScenario, UCommand};

static UCMD_INIT: AtomicBool = AtomicBool::new(false);

fn ucmd() -> (TestScenario, UCommand) {
    if !UCMD_INIT.swap(true, Ordering::Relaxed) {
        unsafe { std::env::set_var("UUTESTS_BINARY_PATH", env!("CARGO_BIN_EXE_file")) };
    }

    let scene = TestScenario::new("file");
    let cmd = scene.cmd(env!("CARGO_BIN_EXE_file"));
    (scene, cmd)
}

#[test]
fn test_brief_mode() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("sample.txt", "Hello World\n");
    cmd.args(&["-b", "sample.txt"])
        .succeeds()
        .stdout_only("ASCII text\n");
}

#[test]
fn test_mime_type_output() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("hello.py", "#!/usr/bin/env python3\nprint(1)\n");
    cmd.args(&["--mime-type", "-b", "hello.py"])
        .succeeds()
        .stdout_only("text/x-script.python\n");
}

#[test]
fn test_mime_all() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("hello.sh", "#!/bin/sh\necho hi\n");
    cmd.args(&["-i", "-b", "hello.sh"])
        .succeeds()
        .stdout_only("text/x-shellscript; charset=us-ascii\n");
}

#[test]
fn test_empty_file() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("empty.txt", "");
    cmd.args(&["-b", "empty.txt"])
        .succeeds()
        .stdout_only("empty\n");
}

#[test]
fn test_directory() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.mkdir("testdir");
    cmd.args(&["-b", "testdir"])
        .succeeds()
        .stdout_only("directory\n");
}

#[test]
fn test_separator() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("foo.txt", "test\n");
    cmd.args(&["-F", " ->", "foo.txt"])
        .succeeds()
        .stdout_only("foo.txt -> ASCII text\n");
}

#[test]
fn test_print0() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("bar.txt", "test\n");
    cmd.args(&["-0", "bar.txt"])
        .succeeds()
        .stdout_only("bar.txt\0ASCII text\n");
}

#[test]
fn test_json_detection() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("data.json", "{\"key\": \"value\", \"count\": 42}\n");
    cmd.args(&["-b", "data.json"])
        .succeeds()
        .stdout_only("JSON text data\n");
}

#[test]
fn test_csv_detection() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("table.csv", "name,age,city\nAlice,30,NYC\nBob,25,LA\n");
    cmd.args(&["-b", "table.csv"])
        .succeeds()
        .stdout_only("CSV text\n");
}

#[test]
fn test_files_from() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("f1.txt", "one\n");
    scene.fixtures.write("f2.txt", "two\n");
    scene.fixtures.write("list.txt", "f1.txt\nf2.txt\n");
    cmd.args(&["-b", "-f", "list.txt"])
        .succeeds()
        .stdout_only("ASCII text\nASCII text\n");
}

#[test]
fn test_help_flag() {
    let (_scene, mut cmd) = ucmd();
    cmd.arg("--help")
        .succeeds();
}

#[test]
fn test_no_dereference_flag() {
    let (scene, mut cmd) = ucmd();
    scene.fixtures.write("sample.txt", "Hello World\n");
    cmd.args(&["-h", "-b", "sample.txt"])
        .succeeds()
        .stdout_only("ASCII text\n");
}

