## Applying Patches to S2E Source Tree

Normally, you don't have to do this manually. `setup.sh` will take care of this for you.

```
cd ~/s2e/source/CRAXplusplus
cp patches/*.patch ~/s2e/source/s2e/.

cd ~/s2e/source/s2e
git apply *.patch
```

## Generating Patches

You might wish to regenerate the patches after modifying `~/s2e/source/s2e/libs2eplugins/src/CMakeLists.txt`.

```
git diff libs2e > libs2e.patch
git diff libs2eplugins > libs2eplugins.patch
```

This will generate two files: `libs2e.patch` and `libs2eplugins.patch`.
