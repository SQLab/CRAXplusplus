# Writing Your Own Module

For instance, suppose we're going to create a module called "MyModule":

1. Create two files in **libs2eplugins/src/s2e/Plugins/CRAX/Modules/**:

   ```cpp
   // libs2eplugins/src/s2e/Plugins/CRAX/Modules/MyModule.h

   #ifndef S2E_PLUGINS_CRAX_MY_MODULE_H
   #define S2E_PLUGINS_CRAX_MY_MODULE_H

   #include <s2e/Plugins/CRAX/Modules/Module.h>

   namespace s2e::plugins::crax {

   class IOStates : public Module {
   public:

       class State : public ModuleState {
       public:
           State() : leakableOffset(), stateInfoList() {}
           virtual ~State() = default;

           static ModuleState *factory(Module *, CRAXState *) {
               return new State();
           }

           virtual ModuleState *clone() const override {
               return new State(*this);
           }

           // Your per-state module data goes here:
           // ...
       };

       explicit IOStates(CRAX &ctx);
       virtual ~IOStates() = default;

       virtual std::string toString() const override {
           return "MyModule";
       }

   private:
       // Module data shared by all execution states goes here:
       // ...
   };

   }  // namespace s2e::plugins::crax

   #endif  // S2E_PLUGINS_CRAX_MY_MODULE_H
   ```

   ```cpp
   // libs2eplugins/src/s2e/Plugins/CRAX/Modules/MyModule.cpp

   #include "MyModule.h"

   namespace s2e::plugins::crax {

   // Declare your module's static data member here.

   // Define your module's method here.

   }  // namespace s2e::plugins::crax
   ```

2. In **libs2eplugins/src/CMakeLists.txt**, remember to add your corresponding .cpp file.
3. In **s2e-config.lua**, make sure to add "MyModule".

   ```lua
   add_plugin("CRAX")

   pluginsConfig.CRAX = {
       -- ...
       -- Modules of CRAX++ that you wish to load.
       modules = {
           "ExploitGenerator",
           "RopChainBuilder",
           "IOStates",
       },
       -- ...
   }
   ```
