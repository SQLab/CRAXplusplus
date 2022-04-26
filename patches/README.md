## Applying Patches to S2E Source Tree

This directory contains the patches that must be applied to S2E in order to build CRAX++.

Normally, you don't have to apply the patches manually, since `setup.sh` will take care of this for you.

```
cd ~/s2e/source/CRAXplusplus
cp patches/*.patch ~/s2e/source/s2e/.

cd ~/s2e/source/s2e
git apply *.patch
```

## Generating Patches Yourself

After creating a file (.cpp/.h) in src/, you'll need to modify `~/s2e/source/s2e/libs2eplugins/src/CMakeLists.txt`. In this case, please regenerate the patches using the following commands:

```
git diff libs2e > libs2e.patch
git diff libs2eplugins > libs2eplugins.patch
```

This will generate two files: `libs2e.patch` and `libs2eplugins.patch`, upload them to this repo.
