# lazyinit

[![Crates.io](https://img.shields.io/crates/v/lazyinit)](https://crates.io/crates/lazyinit)
[![Docs.rs](https://docs.rs/lazyinit/badge.svg)](https://docs.rs/lazyinit)
[![CI](https://github.com/arceos-org/lazyinit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/arceos-org/lazyinit/actions/workflows/ci.yml)

Initialize a static value lazily.

Unlike [`lazy_static`][1], which hardcodes the initialization routine in a macro, you can initialize the value in any way.

[1]: https://docs.rs/lazy_static

## Examples

```rust
use lazyinit::LazyInit;

static VALUE: LazyInit<u32> = LazyInit::new();
assert!(!VALUE.is_inited());
// println!("{}", *VALUE); // panic: use uninitialized value
assert_eq!(VALUE.get(), None);

VALUE.init_once(233);
// VALUE.init_once(666); // panic: already initialized
assert!(VALUE.is_inited());
assert_eq!(*VALUE, 233);
assert_eq!(VALUE.get(), Some(&233));
```

Only one of the multiple initializations can succeed:

```rust
use lazyinit::LazyInit;
use std::time::Duration;

const N: usize = 16;
static VALUE: LazyInit<usize> = LazyInit::new();

let threads = (0..N)
    .map(|i| {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            VALUE.call_once(|| i)
        })
    })
    .collect::<Vec<_>>();

let mut ok = 0;
for (i, thread) in threads.into_iter().enumerate() {
    if thread.join().unwrap().is_some() {
        ok += 1;
        assert_eq!(*VALUE, i);
    }
}

assert_eq!(ok, 1);
```
