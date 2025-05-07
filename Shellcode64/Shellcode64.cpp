#include <iostream>
#include <Windows.h>
using namespace std;

extern "C" void helloworld();

int main()
{
    cout << "Hello World" << endl;
    getchar();
    helloworld();
    return 0;
}
