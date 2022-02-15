# Writing Your Own Module

For example, suppose we're going to create a module called "MyModule":

1. Create a directory named `MyModule` in **libs2eplugins/src/s2e/Plugins/CRAX/Modules/**.

2. In MyModule directory, create two files:
   * MyModule.h
   * MyModule.cpp

   <br>

   ```cpp
   // libs2eplugins/src/s2e/Plugins/CRAX/Modules/MyModule/MyModule.h
   #ifndef S2E_PLUGINS_CRAX_MY_MODULE_H
   #define S2E_PLUGINS_CRAX_MY_MODULE_H

   #include <s2e/Plugins/CRAX/Modules/Module.h>

   namespace s2e::plugins::crax {
   
   class MyModule : public Module {
   public:
       class State : public ModuleState {
       public:
           State() : ModuleState() {}
           virtual ~State() override = default;

           static ModuleState *factory(Module *, CRAXState *) {
               return new State();
           }

           virtual ModuleState *clone() const override {
               return new State(*this);
           }
           
       private:
           // Your per-state module data goes here:
           // ...
       };


       MyModule() = default;
       virtual ~MyModule() override = default;

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
   // libs2eplugins/src/s2e/Plugins/CRAX/Modules/MyModule/MyModule.cpp
   #include "MyModule.h"

   namespace s2e::plugins::crax {

   // Declare your module's static data member here.

   // Define your module's method here.

   }  // namespace s2e::plugins::crax
   ```

2. In **libs2eplugins/src/CMakeLists.txt**, remember to add your corresponding .cpp file.

3. In **s2e-config.template.lua**, make sure to add "MyModule".

   ```lua
   add_plugin("CRAX")

   pluginsConfig.CRAX = {
       -- ...
       -- Modules of CRAX++ that you wish to load.
       modules = {
           "DynamicRop",
           "IOStates",
           "SymbolicAddressMap",
           "MyModule",  -- <-- here
       },
       -- ...
   }
   ```

4. To access per-state module data from MyModule::foo()

   ```cpp
   #include <s2e/Plugins/CRAX/CRAX.h>
   
   void MyModule::foo(S2EExecutionState *state) {
       MyModule::State *modState = g_crax->getModuleState(state, this);
       // ...
   }
   ```

5. To access per-state module data from another module, e.g. ExploitGenerator::foo()

   ```cpp
   #include <s2e/Plugins/CRAX/CRAX.h>
   
   void ExploitGenerator::foo(S2EExecutionState *state) {
       MyModule *mod = CRAX::getModule<MyModule>();
       MyModule::State *modState = g_crax->getModuleState(state, mod);
       // ...
   }
   ```
