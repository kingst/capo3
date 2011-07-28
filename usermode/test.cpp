#include <iostream>

using namespace std;

int main(void) {
    long low, high;
    __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));
    cout << "rdtsc = " << high << " " << low << endl;
    cout << "Hello world!" << endl;
}
