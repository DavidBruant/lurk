# fork of lurk 

fork of [lurk](https://github.com/JakWai01/lurk) to do something else


## tests

You need [nextest](https://nexte.st/docs/installation/pre-built-binaries/)

To run tests : 
```sh
cargo nextest run
```


There were failures with `cargo tests` as soon as i had 2 tests (they ran fine individually)
I haven't inverstigated, but suppose there is a problem with creating 2 Tracer instances simulténeously



