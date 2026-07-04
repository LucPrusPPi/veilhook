#include <gtest/gtest.h>
#include <veilhook/syscalls.hpp>

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    // Initialize our syscalls framework before any tests run
    if (!veilhook::syscalls::init()) {
        std::cerr << "CRITICAL FAILURE: Failed to initialize VeilHook Syscalls (HalosGate)!" << std::endl;
        return 1;
    }

    return RUN_ALL_TESTS();
}
