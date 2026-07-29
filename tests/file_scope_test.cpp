#include <cassert>
#include <filesystem>
#include <string>

#include "utils/file.h"

int main() {
  const std::string fixture = "tests/fixtures/sample-subscription.txt";
  assert(isInScope(fixture));
  assert(fileExist(fixture, true));
  assert(!fileGet(fixture, true).empty());

  assert(!isInScope("../sample-subscription.txt"));
  assert(!isInScope("tests/../sample-subscription.txt"));
  assert(!fileExist("../sample-subscription.txt", true));
  assert(fileGet("../sample-subscription.txt", true).empty());

  const std::string absolute =
      std::filesystem::absolute(fixture).string();
  assert(!isInScope(absolute));
  assert(!fileExist(absolute, true));
  assert(fileGet(absolute, true).empty());
  return 0;
}
