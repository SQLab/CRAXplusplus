## BUILD.md

This file contains the instructions for building S2E and CRAX++.

S2E officially supports 64-bit Ubuntu (18.04, 20.04 LTS), older or later versions may or may not work.

## External Dependencies

You need to manually install some additional tools or packages before building CRAX++.
* [pwntools](https://github.com/Gallopsled/pwntools) (4.7.0)
```
sudo -H python3 -m pip install pwntools==4.7.0
```

* [pybind11-dev](https://github.com/pybind/pybind11) (2.4.3-2build2)
```
sudo apt-get install pybind11-dev=2.4.3-2build2
```

* [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) (6.6)
```
sudo -H python3 -m pip install ROPgadget==6.6
```

## Building S2E Manually

First, we will install **s2e-env**, a command-line tool for creating and administering isolated development environments for S2E.
```
sudo apt-get install git gcc python3 python3-dev python3-venv python3-pip vim neovim tmux

cd
git clone https://github.com/s2e/s2e-env.git
cd s2e-env

python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip
pip install .
```

Create a new S2E environment (which consists of an S2E engine, tools, 1+ VM images, 1+ projects)
```
s2e init $HOME/s2e
```

Exit your shell, start another one:
```
cd
rm -rf s2e-env
exit
```

We'll use the s2e-env in `~/s2e` from now on.
```
cd ~/s2e/source/s2e-env
python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip
pip install .

cd ~/s2e
source s2e_activate
```

Finally, build S2E (~60 mins)
```
s2e build
```

Download pre-built VM images (~30 mins)
```
s2e image_build linux -d
```

## Building CRAX++ Manually

Now let's move on and build CRAX++.
```
cd ~/s2e/source
git clone https://github.com/SQLab/CRAXplusplus
cd CRAXplusplus
```

Build concolic execution proxies.
```
cd ~/s2e/source/CRAXplusplus/proxies/sym_stdin && make
cd ~/s2e/source/CRAXplusplus/proxies/sym_file && make
```

Create an S2E project with our concolic execution proxy, `sym_stdin`.
```
cd ~/s2e
s2e new_project --image debian-9.2.1-x86_64 ~/s2e/source/CRAXplusplus/proxies/sym_stdin/sym_stdin
```

Run `setup.sh`. This applies several patches to the S2E source tree, places some symlinks in your S2E project, and merges the source code of CRAX++ into S2E source tree.
```
cd ~/s2e/source/CRAXplusplus
./setup.sh
```

Rebuild S2E.
```
cd ~/s2e
rm -rf build/stamps/libs2e-release-*
s2e build
```

## Running CRAX++

First, navigate to your S2E project.
```
cd ~/s2e/projects/sym_stdin
```

You'll notice some files within this directory:
* `target` - a symlink to the target executable.
* `poc` - the PoC crash input which will be made symbolic
* `set-target.sh` - a script that automatically sets `target` and `poc` for you.
* `s2e-config.template.lua` - if you wish to modify the config of CRAX++, modify this file.
* `launch-crax.sh` - generates a `s2e-config.lua` from the template and launch CRAX++.

Now, I'll explain the usage of `set-target.sh`. All example targets are located in `~/s2e/source/CRAXplusplus/examples`.
```
> ls -la ~/s2e/source/CRAXplusplus/examples
total 52K
drwxrwxr-x  2 aesophor aesophor 4.0K Feb  5 23:24 aslr-nx
drwxrwxr-x  2 aesophor aesophor 4.0K Jan 28 16:12 aslr-nx-canary
drwxrwxr-x  2 aesophor aesophor 4.0K Feb  4 20:34 aslr-nx-pie
drwxrwxr-x  2 aesophor aesophor 4.0K Feb  6 13:19 aslr-nx-pie-canary
drwxrwxr-x  2 aesophor aesophor 4.0K Feb 12 18:27 aslr-nx-pie-canary-fullrelro
drwxrwxr-x  2 aesophor aesophor 4.0K Feb  5 01:24 b64
drwxrwxr-x  2 aesophor aesophor 4.0K Feb  8 16:50 readme
drwxrwxr-x  2 aesophor aesophor 4.0K Feb  8 16:48 readme-alt1
drwxrwxr-x  2 aesophor aesophor 4.0K Feb  8 16:48 readme-alt2
drwxrwxr-x  2 aesophor aesophor 4.0K Feb 14 15:15 readme-tmp
drwxrwxr-x  2 aesophor aesophor 4.0K Feb  5 01:11 unexploitable
drwxrwxr-x 13 aesophor aesophor 4.0K Feb 14 15:15 .
drwxrwxr-x 10 aesophor aesophor 4.0K Feb 15 17:10 ..
```

Let's select a target to exploit using `set-target.sh`.
```
./set-target.sh aslr-nx
```

Modify `s2e-config.template.lua` and tailor the exploitation techniques to your needs. For `aslr-nx`, use the following techniques:
```
techniques = {
    "Ret2csu",
    "BasicStackPivot",
    "Ret2syscall",
},
```

Launch CRAX++ and let it generate exploit scripts for you!
```
./launch-crax.sh
```

## Reference

http://s2e.systems/docs/s2e-env.html
