# AngryPafish


## Notes

* Compile the binary **without** stripping symbols from it (i.e. remove -s flag from makefile). This makes analysis simpler and check-table auto-generation possible (with the script).

* *msvcrt.dll* (i.e. C standard library) loading is practically necessary, since angr libc simprocedures (willingly?) do not cover the entire library (e.g. toupper, tolower not modelled). That said, the available simprocedures are (probably) still handy so we may still want to use them (**need a clean way to do it**).