#include <iostream>
#include <Windows.h>
using namespace std;

extern "C" void Shellcode();

int main()
{
    cout << "Hello from CPP" << endl;
    getchar();
    Shellcode();
    return 0;
}