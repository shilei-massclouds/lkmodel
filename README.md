# LKModel

A modular OS-Kernel model written in Rust. It's a base on which We study
how to use components to construct various kernels.

Many original components come from [ArceOS](https://github.com/arceos-org/arceos).

Current target is to construct a monolithic kernel which is compatible with Linux-ABI,
i.e. any linux binary user-app can work on lkmodel directly.

## Quick Start

### 1. Preparations

Install [cargo-binutils](https://github.com/rust-embedded/cargo-binutils) to use necessary tools:

```sh
cargo install cargo-binutils
```

Install qemu:

```sh
# for Debian/Ubuntu
sudo apt-get install qemu-system
```

Install ltp - Linux Test Project (a forked version with minor fixes).

Put it into the same parent directory with lkmodel itself.

```sh
git clone git@github.com:shilei-massclouds/ltp.git
cd ltp
make autotools
./mk_riscv64.sh
```

> Directory layout is just as below:

ParentDir

  |

  +---lkmodel

  |

  +---ltp

  |


## 2. Build & Run

```sh
make prepare
make run
```

A monolithic kernel with initial user-app `hello` starts as below:

```console
[userland]: Hello, Init! Sqrt(1048577) = 35190
```

The full form of building command:

```sh
make run LOG=<log> INIT=path/to/user_app
```

`<log>` should be one of `off`, `error`, `warn`, `info`, `debug`, `trace`.

## 3. Test

Run btp tests (internal tests):

```sh
make prepare
make run INIT=/btp/sbin/runbtp
```

Run ltp tests (work in process):

```sh
make prepare
make run INIT=/btp/sbin/runltp
```

Run all base components tower-tests:

```sh
./test_all.sh
```
