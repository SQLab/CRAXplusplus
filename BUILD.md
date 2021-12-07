## BUILD.md


CRAX++ is implemented as a plugin of S2E, and it requires our custom patches for s2e which are only containted in this repository.

This file contains the instructions for building CRAX++.

## Preparation

S2E officially supports 64-bit Ubuntu (18.04, 20.04 LTS, and later versions), older versions may not work.

You need to install some additional tools or packages before building CRAX++. (Note: the annotated version numbers are not mandatory).
* [pwntools](https://github.com/Gallopsled/pwntools) (4.7.0)
* [pybind11-dev](https://github.com/pybind/pybind11) (2.4.3-2build2)
* [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) (6.6)

## Building S2E

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
s2e init /home/aesophor/s2e
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

Clone CRAX++, replace s2e with CRAX++, and build. (~60 mins)

```
cd ~/s2e/source
rm -rf s2e
git clone https://github.com/aesophor/CRAXplusplus s2e

s2e build
```

Download pre-built VM images (~30 mins)
```
s2e image_build linux -d
```

Create an S2E project with our concolic execution wrapper
```
cd ~/s2e/source/s2e/wrappers/symio
make
cd ~/s2e
s2e new_project --image debian-9.2.1-x86_64 source/s2e/wrappers/symio/symio
```

Install CRAX++ configuration.
```
cp source/s2e/wrappers/examples/* projects/symio/.
```

Setup target executable and poc.
```
cd projects/symio
ln -s ~/s2e/examples/rop/rop target
ln -s ~/s2e/examples/rop/poc poc
```

At this point, `target` is a symbolic link pointing to your target executable, and `poc`
is the input which should crash the target.

Finally, launch S2E and let it generate exploit for you!
```
./launch_s2e.sh
```

## Reference

http://s2e.systems/docs/s2e-env.html
