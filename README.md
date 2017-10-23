# angr-antievasion

An extension for the [angr](http://angr.io/) open source binary analysis and symbolic execution framework.

The extension mainly consists of a set of Win32 API patches for the angr framework that constrain the symbolic exploration in order to automatically pass common **evasive** checks.

This tool was originally developed as part of the **Master's Thesis** of the author.  
The original release is available under the *thesis* tag.

The main ideas behind this project are described in the thesis [Symbolic Execution of Malicious Software: Countering Sandbox Evasion Techniques](https://github.com/fabros/angr-antievasion/blob/master/thesis/msc_thesis.pdf).
