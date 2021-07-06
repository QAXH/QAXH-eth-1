# MIT App Inventor Extension for Ethereum

This repository is the java source code used to build the Ethereum extension

This repo is using the extension template from 
https://github.com/mit-cml/extension-template


## to rebuild

You will need:

* java 1.8 (either OpenJDK or Oracle)
  * Do not use Java 8 or newer features as our build system does not
    yet support this.
* ant 1.10 or higher
* git 2.3.10 or higher

After cloning this repository, use the following command:

```shell
git submodule init
git submodule update
```

Then build using ant

This extension is too big to be uploaded on the standard
mit server (ai2.appinventor.mit.edu), it requires a modified server
where the extension upload size limit has been removed.

However, the minimal application (.aia) in the release area can be used
on the standard mit server, it contains this extension and nothing else
and allows to build an application
