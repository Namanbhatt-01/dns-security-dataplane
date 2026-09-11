#include "test_framework.h"

int main() {
    return tdd::TestRegistry::instance().run_all();
}
