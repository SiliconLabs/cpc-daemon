LOCK FILE GENERATION
--------------------

cargo +nightly generate-lockfile -Z minimal-versions
cargo update regex --precise 1.5.6
cargo update shlex --precise 1.3.0
cargo update log --precise 0.4.20
cargo --locked audit
